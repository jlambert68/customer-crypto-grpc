package webapp

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"example.com/customer-crypto-grpc-v2/agent"
)

//go:embed static/*
var staticFiles embed.FS

type Identity struct {
	ID     string   `json:"id"`
	Label  string   `json:"label"`
	Role   string   `json:"role"`
	Read   []string `json:"read"`
	Update []string `json:"update"`
}

type server struct {
	identityDir string
	grpcAddr    string
	logger      *slog.Logger
	identities  []Identity
	byID        map[string]Identity
	objects     []string
	objectSet   map[string]bool
	requestID   atomic.Uint64
	static      http.Handler
}

type recordResponse struct {
	Actor     string         `json:"actor"`
	ObjectID  string         `json:"object_id"`
	Version   uint64         `json:"version"`
	CanUpdate bool           `json:"can_update"`
	Data      map[string]any `json:"data"`
}

type contextKey string

const requestIDKey contextKey = "request-id"

func NewHandler(identityDir, grpcAddr string, logger *slog.Logger) (http.Handler, error) {
	if logger == nil {
		logger = slog.Default()
	}
	identities := []Identity{
		{ID: "customer1", Label: "Customer 1", Role: "customer", Read: []string{"C001"}, Update: []string{"C001"}},
		{ID: "customer2", Label: "Customer 2", Role: "customer", Read: []string{"C002"}, Update: []string{"C002"}},
		{ID: "customer3", Label: "Customer 3", Role: "customer", Read: []string{"C003"}, Update: []string{"C003"}},
		{ID: "backoffice1", Label: "Back office 1", Role: "backoffice", Read: []string{"C001", "C002"}, Update: []string{}},
		{ID: "backoffice2", Label: "Back office 2", Role: "backoffice", Read: []string{"C002", "C003"}, Update: []string{}},
	}
	byID := make(map[string]Identity, len(identities))
	for _, identity := range identities {
		path := filepath.Join(identityDir, identity.ID+".json")
		info, e := os.Stat(path)
		if e != nil {
			return nil, fmt.Errorf("identity %s is unavailable at %s: %w", identity.ID, path, e)
		}
		if info.Mode().Perm()&0077 != 0 {
			logger.Warn("identity file permissions are broader than 0600", "identity", identity.ID, "mode", info.Mode().Perm())
		}
		byID[identity.ID] = identity
	}
	assets, e := fs.Sub(staticFiles, "static")
	if e != nil {
		return nil, e
	}
	objects := []string{"C001", "C002", "C003"}
	s := &server{
		identityDir: identityDir,
		grpcAddr:    grpcAddr,
		logger:      logger,
		identities:  identities,
		byID:        byID,
		objects:     objects,
		objectSet:   map[string]bool{"C001": true, "C002": true, "C003": true},
		static:      http.FileServer(http.FS(assets)),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", s.health)
	mux.HandleFunc("GET /api/v1/config", s.config)
	mux.HandleFunc("GET /api/v1/records/{object}", s.readRecord)
	mux.HandleFunc("PATCH /api/v1/records/{object}", s.updateRecord)
	mux.Handle("GET /", s.static)
	return s.logRequests(mux), nil
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) config(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"identities": s.identities,
		"objects":    s.objects,
		"warning":    "Local educational demo: selecting an identity impersonates it using credentials stored by this gateway.",
	})
}

func (s *server) readRecord(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.requireIdentity(w, r)
	if !ok {
		return
	}
	object, ok := s.requireObject(w, r)
	if !ok {
		return
	}
	a, e := agent.Connect(filepath.Join(s.identityDir, identity.ID+".json"), s.grpcAddr)
	if e != nil {
		s.operationError(w, r, "connect", identity.ID, object, e)
		return
	}
	defer a.Close()
	o, plain, e := a.Read(object, 0)
	if e != nil {
		s.operationError(w, r, "read", identity.ID, object, e)
		return
	}
	data, e := decodeRecord(plain)
	if e != nil {
		s.operationError(w, r, "decode", identity.ID, object, e)
		return
	}
	s.logger.Info("record read", "request_id", requestID(r), "actor", identity.ID, "object", object, "version", o.Version)
	writeJSON(w, http.StatusOK, recordResponse{Actor: identity.ID, ObjectID: object, Version: o.Version, CanUpdate: contains(identity.Update, object), Data: data})
}

func (s *server) updateRecord(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.requireIdentity(w, r)
	if !ok {
		return
	}
	object, ok := s.requireObject(w, r)
	if !ok {
		return
	}
	contentType, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || contentType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var input struct {
		Changes map[string]string `json:"changes"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if e := decoder.Decode(&input); e != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON request: "+e.Error())
		return
	}
	if e := ensureEOF(decoder); e != nil {
		writeError(w, http.StatusBadRequest, "request body must contain one JSON object")
		return
	}
	a, e := agent.Connect(filepath.Join(s.identityDir, identity.ID+".json"), s.grpcAddr)
	if e != nil {
		s.operationError(w, r, "connect", identity.ID, object, e)
		return
	}
	defer a.Close()
	version, plain, e := a.UpdateFields(object, input.Changes)
	if e != nil {
		s.operationError(w, r, "update", identity.ID, object, e)
		return
	}
	data, e := decodeRecord(plain)
	if e != nil {
		s.operationError(w, r, "decode", identity.ID, object, e)
		return
	}
	s.logger.Info("record updated", "request_id", requestID(r), "actor", identity.ID, "object", object, "version", version, "fields", sortedKeys(input.Changes))
	writeJSON(w, http.StatusOK, recordResponse{Actor: identity.ID, ObjectID: object, Version: version, CanUpdate: contains(identity.Update, object), Data: data})
}

func (s *server) requireIdentity(w http.ResponseWriter, r *http.Request) (Identity, bool) {
	id := strings.TrimSpace(r.Header.Get("X-Demo-Identity"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "X-Demo-Identity header is required")
		return Identity{}, false
	}
	identity, ok := s.byID[id]
	if !ok {
		writeError(w, http.StatusUnauthorized, "unknown demo identity")
		return Identity{}, false
	}
	return identity, true
}

func (s *server) requireObject(w http.ResponseWriter, r *http.Request) (string, bool) {
	object := r.PathValue("object")
	if !s.objectSet[object] {
		writeError(w, http.StatusNotFound, "unknown customer record")
		return "", false
	}
	return object, true
}

func (s *server) operationError(w http.ResponseWriter, r *http.Request, operation, actor, object string, e error) {
	status := http.StatusBadGateway
	message := e.Error()
	switch {
	case strings.Contains(message, "unauthorized"):
		status = http.StatusUnauthorized
	case strings.Contains(message, "access denied"), strings.Contains(message, "principal revoked"), strings.Contains(message, "only the customer who owns"):
		status = http.StatusForbidden
	case strings.Contains(message, "cannot be updated"), strings.Contains(message, "at least one field"), strings.Contains(message, "does not match"):
		status = http.StatusBadRequest
	case strings.Contains(message, "no rows"):
		status = http.StatusNotFound
	}
	s.logger.Warn("record operation failed", "request_id", requestID(r), "operation", operation, "actor", actor, "object", object, "status", status, "error", message)
	writeError(w, status, message)
}

func (s *server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := fmt.Sprintf("req-%06d", s.requestID.Add(1))
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		r = r.WithContext(ctx)
		w.Header().Set("X-Request-ID", id)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'")
		started := time.Now()
		recorder := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("http panic", "request_id", id, "panic", recovered)
				if !recorder.wroteHeader {
					writeError(recorder, http.StatusInternalServerError, "internal server error")
				}
			}
			host, _, e := net.SplitHostPort(r.RemoteAddr)
			if e != nil {
				host = r.RemoteAddr
			}
			s.logger.Info("http request", "request_id", id, "method", r.Method, "path", r.URL.Path, "actor", r.Header.Get("X-Demo-Identity"), "status", recorder.status, "bytes", recorder.bytes, "duration", time.Since(started).Round(time.Microsecond), "remote", host)
		}()
		next.ServeHTTP(recorder, r)
	})
}

type responseRecorder struct {
	http.ResponseWriter
	status      int
	bytes       int
	wroteHeader bool
}

func (r *responseRecorder) WriteHeader(status int) {
	if r.wroteHeader {
		return
	}
	r.status = status
	r.wroteHeader = true
	r.ResponseWriter.WriteHeader(status)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	n, e := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, e
}

func requestID(r *http.Request) string {
	id, _ := r.Context().Value(requestIDKey).(string)
	return id
}

func decodeRecord(plain []byte) (map[string]any, error) {
	var data map[string]any
	if e := json.Unmarshal(plain, &data); e != nil {
		return nil, fmt.Errorf("stored customer data is invalid: %w", e)
	}
	return data, nil
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	e := decoder.Decode(&extra)
	if errors.Is(e, io.EOF) {
		return nil
	}
	if e == nil {
		return errors.New("extra JSON value")
	}
	return e
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for _, key := range []string{"name", "email", "phone", "city", "notes"} {
		if _, ok := values[key]; ok {
			keys = append(keys, key)
		}
	}
	return keys
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
