package agent

import (
	"context"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"example.com/customer-crypto-grpc-v2/core"
	"example.com/customer-crypto-grpc-v2/protocol"
	"example.com/customer-crypto-grpc-v2/service"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"math/big"
	"os"
	"time"
)

type Identity struct {
	ID     string `json:"id"`
	Token  string `json:"token"`
	Secret []byte `json:"secret"`
}
type Agent struct {
	ID                      Identity
	Conn                    *grpc.ClientConn
	BypassReadAuthorization bool
}

func Connect(path, addr string) (*Agent, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	var id Identity
	if e = json.Unmarshal(b, &id); e != nil {
		return nil, e
	}
	c, e := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDefaultCallOptions(grpc.ForceCodec(protocol.JSONCodec{})))
	if e != nil {
		return nil, e
	}
	return &Agent{ID: id, Conn: c}, nil
}
func (a *Agent) Close() { a.Conn.Close() }
func (a *Agent) Call(op string, req any, out any) error {
	b, e := json.Marshal(req)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	metadataPairs := []string{"client-id", a.ID.ID, "authorization", a.ID.Token}
	if a.BypassReadAuthorization {
		metadataPairs = append(metadataPairs, service.ReadAuthorizationMetadata, "disabled")
	}
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(metadataPairs...))
	return protocol.Invoke(ctx, a.Conn, op, &protocol.Request{Payload: b}, out)
}
func (a *Agent) Publics(obj string) (map[string]core.Point, error) {
	var pubs []service.Pub
	if e := a.Call("pubs", service.ObjectArgs{Object: obj}, &pubs); e != nil {
		return nil, e
	}
	out := map[string]core.Point{}
	for _, p := range pubs {
		x, y := elliptic.Unmarshal(elliptic.P256(), p.Public)
		point := core.Point{X: x, Y: y}
		if !core.Valid(point) {
			return nil, errors.New("invalid public key")
		}
		out[p.ID] = point
	}
	return out, nil
}
func (a *Agent) Fetch(obj string, v uint64) (core.Object, error) {
	snap, e := a.FetchSnapshot(obj, v)
	return snap.Data, e
}
func (a *Agent) FetchSnapshot(obj string, v uint64) (service.Snapshot, error) {
	var snap service.Snapshot
	e := a.Call("fetch", service.ObjectArgs{Object: obj, Version: v}, &snap)
	return snap, e
}
func (a *Agent) Read(obj string, v uint64) (core.Object, []byte, error) {
	o, e := a.Fetch(obj, v)
	if e != nil {
		return core.Object{}, nil, e
	}
	plain, e := a.Decrypt(o)
	return o, plain, e
}
func (a *Agent) Partial(obj core.Object) (core.Point, error) {
	env, ok := obj.Envelopes[a.ID.ID]
	if !ok {
		return core.Point{}, errors.New("no recipient envelope")
	}
	var r service.PartialReply
	e := a.Call("partial", service.PartialArgs{Object: obj.ID, Version: obj.Version, R: service.EncodePoint(env.R)}, &r)
	if e != nil {
		return core.Point{}, e
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), r.Point)
	p := core.Point{X: x, Y: y}
	if !core.Valid(p) {
		return p, errors.New("invalid server partial")
	}
	return p, nil
}
func (a *Agent) Decrypt(obj core.Object) ([]byte, error) {
	plain, _, e := a.DecryptWithDEK(obj)
	return plain, e
}
func (a *Agent) DecryptWithDEK(obj core.Object) ([]byte, []byte, error) {
	plain, trace, e := a.DecryptWithTrace(obj)
	return plain, trace.DEK, e
}
func (a *Agent) DecryptWithTrace(obj core.Object) ([]byte, core.DecryptionTrace, error) {
	p, e := a.Partial(obj)
	if e != nil {
		return nil, core.DecryptionTrace{}, e
	}
	return a.FinalWithTrace(obj, p)
}
func (a *Agent) Final(obj core.Object, p core.Point) ([]byte, error) {
	plain, _, e := a.FinalWithDEK(obj, p)
	return plain, e
}
func (a *Agent) FinalWithDEK(obj core.Object, p core.Point) ([]byte, []byte, error) {
	plain, trace, e := a.FinalWithTrace(obj, p)
	return plain, trace.DEK, e
}
func (a *Agent) FinalWithTrace(obj core.Object, p core.Point) ([]byte, core.DecryptionTrace, error) {
	n := new(big.Int).SetBytes(a.ID.Secret)
	if n.Sign() == 0 {
		return nil, core.DecryptionTrace{}, errors.New("empty private share")
	}
	return core.FinalWithTrace(obj, core.Client{ID: a.ID.ID, Secret: n}, p)
}
func (a *Agent) Upload(obj core.Object) error {
	var r service.Empty
	return a.Call("upload", service.UploadArgs{Object: obj}, &r)
}
func (a *Agent) EncryptAndUpload(id string, v uint64, plain []byte) error {
	pubs, e := a.Publics(id)
	if e != nil {
		return e
	}
	obj, e := core.Encrypt(id, v, plain, pubs)
	if e != nil {
		return e
	}
	return a.Upload(obj)
}
func (a *Agent) UpdateFields(id string, changes map[string]string) (uint64, []byte, error) {
	if len(changes) == 0 {
		return 0, nil, errors.New("at least one field must be changed")
	}
	o, plain, e := a.Read(id, 0)
	if e != nil {
		return 0, nil, e
	}
	var record map[string]any
	if e = json.Unmarshal(plain, &record); e != nil {
		return 0, nil, fmt.Errorf("stored customer data is not a JSON object: %w", e)
	}
	if customerID, ok := record["customer_id"].(string); !ok || customerID != id {
		return 0, nil, errors.New("stored customer_id does not match the requested object")
	}
	allowed := map[string]bool{"name": true, "email": true, "phone": true, "city": true, "notes": true}
	for field, value := range changes {
		if !allowed[field] {
			return 0, nil, fmt.Errorf("field %q cannot be updated", field)
		}
		record[field] = value
	}
	updated, e := json.Marshal(record)
	if e != nil {
		return 0, nil, e
	}
	next := o.Version + 1
	if e = a.EncryptAndUpload(id, next, updated); e != nil {
		return 0, nil, e
	}
	return next, updated, nil
}
func (a *Agent) Rotate(id string, next uint64) error {
	old, e := a.Fetch(id, next-1)
	if e != nil {
		return e
	}
	plain, e := a.Decrypt(old)
	if e != nil {
		return e
	}
	if e = a.EncryptAndUpload(id, next, plain); e != nil {
		return e
	}
	fmt.Printf("rotated %s to version %d (plaintext stayed in rotation process)\n", id, next)
	return nil
}
