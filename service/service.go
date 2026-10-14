package service

import (
	"context"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"example.com/customer-crypto-grpc-v2/core"
	"example.com/customer-crypto-grpc-v2/protocol"
	"example.com/customer-crypto-grpc-v2/storage"
	"google.golang.org/grpc/metadata"
)

type Service struct{ Store *storage.Store }
type Pub struct {
	ID     string `json:"id"`
	Public []byte `json:"public"`
}
type Snapshot struct {
	ID      string          `json:"id"`
	Version uint64          `json:"version"`
	Data    core.Object     `json:"data"`
	Stored  json.RawMessage `json:"stored"`
}
type Job struct {
	ID   string `json:"id"`
	Next uint64 `json:"next"`
}
type Empty struct{}
type PartialArgs struct {
	Object  string `json:"object"`
	Version uint64 `json:"version"`
	R       []byte `json:"r"`
}
type PartialReply struct {
	Point []byte `json:"point"`
}
type UploadArgs struct {
	Object core.Object `json:"object"`
}
type ObjectArgs struct {
	Object  string `json:"object"`
	Version uint64 `json:"version"`
}
type RevokeArgs struct {
	ID string `json:"id"`
}

const ReadAuthorizationMetadata = "demo-read-authorization"

func point(b []byte) (core.Point, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), b)
	p := core.Point{X: x, Y: y}
	if !core.Valid(p) {
		return p, errors.New("invalid point")
	}
	return p, nil
}
func EncodePoint(p core.Point) []byte { return elliptic.Marshal(elliptic.P256(), p.X, p.Y) }
func Scalar(b []byte) (*big.Int, error) {
	n := new(big.Int).SetBytes(b)
	if n.Sign() <= 0 || n.Cmp(elliptic.P256().Params().N) >= 0 {
		return nil, errors.New("invalid scalar")
	}
	return n, nil
}
func (s *Service) Call(ctx context.Context, req *protocol.Request) (*protocol.Response, error) {
	fail := func(e error) (*protocol.Response, error) { return &protocol.Response{Error: e.Error()}, nil }
	md, _ := metadata.FromIncomingContext(ctx)
	id := strings.Join(md.Get("client-id"), "")
	token := strings.Join(md.Get("authorization"), "")
	if id == "" || s.Store.CheckToken(id, token) != nil {
		return fail(errors.New("unauthorized"))
	}
	role, secret, _, _, revoked, e := s.Store.Principal(id)
	if e != nil {
		return fail(e)
	}
	if revoked {
		return fail(errors.New("principal revoked"))
	}
	enforceReadAuthorization := !strings.EqualFold(strings.Join(md.Get(ReadAuthorizationMetadata), ""), "disabled")
	result, err := s.execute(req.Target, req.Payload, id, role, secret, enforceReadAuthorization)
	if err != nil {
		return fail(err)
	}
	b, e := json.Marshal(result)
	if e != nil {
		return fail(e)
	}
	_ = s.Store.Exec(`INSERT INTO audit(principal_id,action,object_id) VALUES(?,?,?)`, id, req.Target, "")
	return &protocol.Response{Payload: b}, nil
}
func (s *Service) execute(op string, raw []byte, id, role string, secret []byte, enforceReadAuthorization bool) (any, error) {
	switch op {
	case "pubs":
		var a ObjectArgs
		if e := json.Unmarshal(raw, &a); e != nil {
			return nil, e
		}
		if !s.Store.Authorized(id, a.Object) {
			return nil, errors.New("access denied")
		}
		ids, e := s.Store.GrantIDs(a.Object)
		if e != nil {
			return nil, e
		}
		out := []Pub{}
		for _, who := range ids {
			_, _, sp, cp, rev, e := s.Store.Principal(who)
			if e != nil || rev {
				return nil, errors.New("principal missing")
			}
			p1, e := point(sp)
			if e != nil {
				return nil, e
			}
			p2, e := point(cp)
			if e != nil {
				return nil, e
			}
			p, e := core.Add(p1, p2)
			if e != nil {
				return nil, e
			}
			out = append(out, Pub{who, EncodePoint(p)})
		}
		return out, nil
	case "fetch":
		var a ObjectArgs
		if e := json.Unmarshal(raw, &a); e != nil {
			return nil, e
		}
		if enforceReadAuthorization && !s.Store.Authorized(id, a.Object) {
			return nil, errors.New("access denied")
		}
		v := a.Version
		if v == 0 {
			var e error
			v, e = s.Store.Current(a.Object)
			if e != nil {
				return nil, e
			}
		}
		b, e := s.Store.Object(a.Object, v)
		if e != nil {
			return nil, e
		}
		var obj core.Object
		if e = json.Unmarshal(b, &obj); e != nil {
			return nil, e
		}
		return Snapshot{ID: a.Object, Version: v, Data: obj, Stored: json.RawMessage(append([]byte(nil), b...))}, nil
	case "partial":
		var a PartialArgs
		if e := json.Unmarshal(raw, &a); e != nil {
			return nil, e
		}
		if enforceReadAuthorization && !s.Store.Authorized(id, a.Object) {
			return nil, errors.New("access denied")
		}
		b, e := s.Store.Object(a.Object, a.Version)
		if e != nil {
			return nil, e
		}
		var obj core.Object
		if e = json.Unmarshal(b, &obj); e != nil {
			return nil, e
		}
		env, ok := obj.Envelopes[id]
		if !ok {
			return nil, errors.New("no envelope")
		}
		if string(a.R) != string(EncodePoint(env.R)) {
			return nil, errors.New("ephemeral point mismatch")
		}
		r, e := point(a.R)
		if e != nil {
			return nil, e
		}
		n, e := Scalar(secret)
		if e != nil {
			return nil, e
		}
		p, e := core.Mul(r, n)
		if e != nil {
			return nil, e
		}
		return PartialReply{EncodePoint(p)}, nil
	case "upload":
		var a UploadArgs
		if e := json.Unmarshal(raw, &a); e != nil {
			return nil, e
		}
		o := a.Object
		if !s.Store.Authorized(id, o.ID) {
			return nil, errors.New("access denied")
		}
		if len(o.Ciphertext) == 0 || len(o.Nonce) != 12 {
			return nil, errors.New("invalid ciphertext")
		}
		ids, e := s.Store.GrantIDs(o.ID)
		if e != nil {
			return nil, e
		}
		if len(ids) != len(o.Envelopes) {
			return nil, errors.New("envelope recipient mismatch")
		}
		for _, who := range ids {
			env, ok := o.Envelopes[who]
			if !ok || !core.Valid(env.R) || len(env.Nonce) != 12 || len(env.Wrapped) == 0 {
				return nil, fmt.Errorf("invalid envelope for %s", who)
			}
		}
		v, e := s.Store.Current(o.ID)
		if e != nil {
			return nil, e
		}
		mode := storage.WriteInitial
		switch {
		case v == 0 && role != "rotation":
			return nil, errors.New("only rotation principal can initialize demo data")
		case v > 0 && role == "rotation":
			mode = storage.WriteRotation
		case v > 0 && role == "customer" && s.Store.Owner(id, o.ID):
			mode = storage.WriteOwnerUpdate
		case v > 0:
			return nil, errors.New("only the customer who owns the record can update it")
		}
		b, e := json.Marshal(o)
		if e != nil {
			return nil, e
		}
		return Empty{}, s.Store.Put(o.ID, o.Version, b, mode)
	case "revoke":
		if role != "rotation" {
			return nil, errors.New("rotation role required")
		}
		var a RevokeArgs
		if e := json.Unmarshal(raw, &a); e != nil {
			return nil, e
		}
		return Empty{}, s.Store.Revoke(a.ID)
	case "jobs":
		if role != "rotation" {
			return nil, errors.New("rotation role required")
		}
		ids, e := s.Store.Pending()
		if e != nil {
			return nil, e
		}
		out := []Job{}
		for _, oid := range ids {
			v, _, e := s.Store.RotationJob(oid)
			if e != nil {
				return nil, e
			}
			out = append(out, Job{oid, v})
		}
		return out, nil
	default:
		return nil, errors.New("unknown operation")
	}
}
