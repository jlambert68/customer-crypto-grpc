package webapp

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"embed"
	"encoding/hex"
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
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"example.com/customer-crypto-grpc-v2/agent"
	"example.com/customer-crypto-grpc-v2/core"
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
	Actor             string         `json:"actor"`
	ObjectID          string         `json:"object_id"`
	Version           uint64         `json:"version"`
	CanUpdate         bool           `json:"can_update"`
	AuthorizationMode string         `json:"authorization_mode"`
	DatabaseStored    string         `json:"database_stored"`
	Decrypted         bool           `json:"decrypted"`
	DecryptionError   string         `json:"decryption_error,omitempty"`
	Data              map[string]any `json:"data,omitempty"`
	KeyMaterial       keyMaterial    `json:"key_material"`
	ProcessTrace      processTrace   `json:"process_trace"`
}

type processTrace struct {
	Status                 string   `json:"status"`
	Operation              string   `json:"operation"`
	Actor                  string   `json:"actor"`
	ObjectID               string   `json:"object_id"`
	Version                uint64   `json:"version"`
	AuthorizationMode      string   `json:"authorization_mode"`
	Authenticated          bool     `json:"authenticated"`
	AuthorizationDecision  string   `json:"authorization_decision"`
	DatabaseRead           bool     `json:"database_read"`
	StoredJSONBytes        int      `json:"stored_json_bytes"`
	CiphertextBytes        int      `json:"ciphertext_bytes"`
	RecordNonceHex         string   `json:"record_nonce_hex"`
	Recipients             []string `json:"recipients"`
	EnvelopeFound          bool     `json:"envelope_found"`
	EnvelopeRecipient      string   `json:"envelope_recipient,omitempty"`
	EphemeralPointHex      string   `json:"ephemeral_point_hex,omitempty"`
	WrapNonceHex           string   `json:"wrap_nonce_hex,omitempty"`
	WrappedDEKHex          string   `json:"wrapped_dek_hex,omitempty"`
	ServerPartialPointHex  string   `json:"server_partial_point_hex,omitempty"`
	ClientPartialPointHex  string   `json:"client_partial_point_hex,omitempty"`
	CombinedSharedPointHex string   `json:"combined_shared_point_hex,omitempty"`
	EnvelopeAADHex         string   `json:"envelope_aad_hex,omitempty"`
	KeyEncryptionKeyHex    string   `json:"key_encryption_key_hex,omitempty"`
	DEKHex                 string   `json:"dek_hex,omitempty"`
	RecordAADHex           string   `json:"record_aad_hex,omitempty"`
	PlaintextBytes         int      `json:"plaintext_bytes,omitempty"`
	StopReason             string   `json:"stop_reason,omitempty"`
}

type keyMaterial struct {
	DEKHex        string              `json:"dek_hex,omitempty"`
	RecoveredBy   string              `json:"recovered_by,omitempty"`
	RecipientDEKs []recipientEnvelope `json:"recipient_envelopes"`
}

type recipientEnvelope struct {
	Recipient     string `json:"recipient"`
	Selected      bool   `json:"selected"`
	WrapNonceHex  string `json:"wrap_nonce_hex"`
	WrappedDEKHex string `json:"wrapped_dek_hex"`
}

type contextKey string

const (
	requestIDKey            contextKey = "request-id"
	readAuthorizationHeader            = "X-Demo-Read-Authorization"
)

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
		{ID: "rotation", Label: "Rotation service (privileged)", Role: "rotation", Read: []string{"C001", "C002", "C003"}, Update: []string{}},
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
		"warning":    "Local educational demo: selecting an identity, including the privileged rotation service, impersonates it using credentials stored by this gateway.",
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
	bypassAuthorization := readAuthorizationBypassed(r)
	a.BypassReadAuthorization = bypassAuthorization
	snapshot, e := a.FetchSnapshot(object, 0)
	if e != nil {
		s.operationError(w, r, "fetch", identity.ID, object, e)
		return
	}
	response := recordResponse{
		Actor:             identity.ID,
		ObjectID:          object,
		Version:           snapshot.Version,
		CanUpdate:         contains(identity.Update, object),
		AuthorizationMode: readAuthorizationMode(r),
		DatabaseStored:    formatStoredJSON(snapshot.Stored),
		KeyMaterial:       describeKeyMaterial(snapshot.Data, identity.ID, nil),
		ProcessTrace:      describeProcessTrace(snapshot.Data, len(snapshot.Stored), identity.ID, readAuthorizationMode(r), "read", nil, nil, ""),
	}
	plain, cryptoTrace, e := a.DecryptWithTrace(snapshot.Data)
	if e != nil && bypassAuthorization {
		response.DecryptionError = decryptionFailure(identity.ID, object, e)
		response.ProcessTrace = describeProcessTrace(snapshot.Data, len(snapshot.Stored), identity.ID, response.AuthorizationMode, "read", nil, nil, response.DecryptionError)
		s.logger.Info("ciphertext read but decryption blocked", "request_id", requestID(r), "actor", identity.ID, "object", object, "version", snapshot.Version, "read_authorization", response.AuthorizationMode, "reason", e.Error())
		writeJSON(w, http.StatusOK, response)
		return
	}
	if e != nil {
		s.operationError(w, r, "decrypt", identity.ID, object, e)
		return
	}
	data, e := decodeRecord(plain)
	if e != nil {
		s.operationError(w, r, "decode", identity.ID, object, e)
		return
	}
	response.Decrypted = true
	response.Data = data
	response.KeyMaterial = describeKeyMaterial(snapshot.Data, identity.ID, cryptoTrace.DEK)
	response.ProcessTrace = describeProcessTrace(snapshot.Data, len(snapshot.Stored), identity.ID, response.AuthorizationMode, "read", &cryptoTrace, plain, "")
	s.logger.Info("record read", "request_id", requestID(r), "actor", identity.ID, "object", object, "version", snapshot.Version, "read_authorization", response.AuthorizationMode)
	writeJSON(w, http.StatusOK, response)
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
	if !contains(identity.Update, object) {
		writeError(w, http.StatusForbidden, "only the customer who owns the record can update it")
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
	snapshot, e := a.FetchSnapshot(object, version)
	if e != nil {
		s.operationError(w, r, "fetch updated record", identity.ID, object, e)
		return
	}
	verifiedPlain, cryptoTrace, e := a.DecryptWithTrace(snapshot.Data)
	if e != nil {
		s.operationError(w, r, "unwrap updated DEK", identity.ID, object, e)
		return
	}
	s.logger.Info("record updated", "request_id", requestID(r), "actor", identity.ID, "object", object, "version", version, "fields", sortedKeys(input.Changes))
	writeJSON(w, http.StatusOK, recordResponse{
		Actor:             identity.ID,
		ObjectID:          object,
		Version:           version,
		CanUpdate:         contains(identity.Update, object),
		AuthorizationMode: "enforced",
		DatabaseStored:    formatStoredJSON(snapshot.Stored),
		Decrypted:         true,
		Data:              data,
		KeyMaterial:       describeKeyMaterial(snapshot.Data, identity.ID, cryptoTrace.DEK),
		ProcessTrace:      describeProcessTrace(snapshot.Data, len(snapshot.Stored), identity.ID, "enforced", "update", &cryptoTrace, verifiedPlain, ""),
	})
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
			s.logger.Info("http request", "request_id", id, "method", r.Method, "path", r.URL.Path, "actor", r.Header.Get("X-Demo-Identity"), "read_authorization", readAuthorizationMode(r), "status", recorder.status, "bytes", recorder.bytes, "duration", time.Since(started).Round(time.Microsecond), "remote", host)
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

func readAuthorizationBypassed(r *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(r.Header.Get(readAuthorizationHeader)), "disabled")
}

func readAuthorizationMode(r *http.Request) string {
	if readAuthorizationBypassed(r) {
		return "bypassed"
	}
	return "enforced"
}

func decryptionFailure(actor, object string, e error) string {
	if strings.Contains(e.Error(), "no recipient envelope") || strings.Contains(e.Error(), "missing envelope") {
		return fmt.Sprintf("%s received ciphertext for %s but has no recipient envelope, so its data-encryption key remains unavailable", actor, object)
	}
	return "the selected identity received ciphertext but could not decrypt it: " + e.Error()
}

func describeKeyMaterial(object core.Object, actor string, dek []byte) keyMaterial {
	recipients := make([]string, 0, len(object.Envelopes))
	for recipient := range object.Envelopes {
		recipients = append(recipients, recipient)
	}
	sort.Strings(recipients)
	result := keyMaterial{RecipientDEKs: make([]recipientEnvelope, 0, len(recipients))}
	if len(dek) > 0 {
		result.DEKHex = hex.EncodeToString(dek)
		result.RecoveredBy = actor
	}
	for _, recipient := range recipients {
		envelope := object.Envelopes[recipient]
		result.RecipientDEKs = append(result.RecipientDEKs, recipientEnvelope{
			Recipient:     recipient,
			Selected:      recipient == actor,
			WrapNonceHex:  hex.EncodeToString(envelope.Nonce),
			WrappedDEKHex: hex.EncodeToString(envelope.Wrapped),
		})
	}
	return result
}

func describeProcessTrace(object core.Object, storedBytes int, actor, authorizationMode, operation string, cryptoTrace *core.DecryptionTrace, plaintext []byte, stopReason string) processTrace {
	recipients := make([]string, 0, len(object.Envelopes))
	for recipient := range object.Envelopes {
		recipients = append(recipients, recipient)
	}
	sort.Strings(recipients)

	decision := "read ACL granted"
	if authorizationMode == "bypassed" {
		decision = "read ACL bypassed for this demo; authentication still passed"
	}
	if operation == "update" {
		decision = "owner update accepted; the new encrypted version was fetched with read ACL enforced"
	}

	result := processTrace{
		Status:                "database-returned",
		Operation:             operation,
		Actor:                 actor,
		ObjectID:              object.ID,
		Version:               object.Version,
		AuthorizationMode:     authorizationMode,
		Authenticated:         true,
		AuthorizationDecision: decision,
		DatabaseRead:          true,
		StoredJSONBytes:       storedBytes,
		CiphertextBytes:       len(object.Ciphertext),
		RecordNonceHex:        hex.EncodeToString(object.Nonce),
		Recipients:            recipients,
		RecordAADHex:          hex.EncodeToString(core.AAD(object.ID, object.Version, "")),
		StopReason:            stopReason,
	}
	if envelope, ok := object.Envelopes[actor]; ok {
		result.EnvelopeFound = true
		result.EnvelopeRecipient = actor
		result.EphemeralPointHex = pointHex(envelope.R)
		result.WrapNonceHex = hex.EncodeToString(envelope.Nonce)
		result.WrappedDEKHex = hex.EncodeToString(envelope.Wrapped)
		result.EnvelopeAADHex = hex.EncodeToString(core.AAD(object.ID, object.Version, actor))
	}
	if stopReason != "" {
		result.Status = "blocked"
		return result
	}
	if cryptoTrace == nil {
		return result
	}
	result.Status = "completed"
	result.ServerPartialPointHex = pointHex(cryptoTrace.ServerPartial)
	result.ClientPartialPointHex = pointHex(cryptoTrace.ClientPartial)
	result.CombinedSharedPointHex = pointHex(cryptoTrace.CombinedShared)
	result.KeyEncryptionKeyHex = hex.EncodeToString(cryptoTrace.KeyEncryptionKey)
	result.DEKHex = hex.EncodeToString(cryptoTrace.DEK)
	result.PlaintextBytes = len(plaintext)
	return result
}

func pointHex(point core.Point) string {
	if !core.Valid(point) {
		return ""
	}
	return hex.EncodeToString(elliptic.Marshal(elliptic.P256(), point.X, point.Y))
}

func formatStoredJSON(raw json.RawMessage) string {
	var formatted bytes.Buffer
	if e := json.Indent(&formatted, raw, "", "  "); e != nil {
		return string(raw)
	}
	return formatted.String()
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
