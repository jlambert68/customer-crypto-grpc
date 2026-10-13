package protocol

import (
	"context"
	"encoding/json"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
)

type JSONCodec struct{}

func (JSONCodec) Marshal(v any) ([]byte, error)   { return json.Marshal(v) }
func (JSONCodec) Unmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
func (JSONCodec) Name() string                    { return "json" }
func init()                                       { encoding.RegisterCodec(JSONCodec{}) }

type Request struct {
	ClientID string `json:"client_id,omitempty"`
	ObjectID string `json:"object_id,omitempty"`
	Version  uint64 `json:"version,omitempty"`
	Payload  []byte `json:"payload,omitempty"`
	Target   string `json:"target,omitempty"`
}
type Response struct {
	Payload []byte `json:"payload,omitempty"`
	Error   string `json:"error,omitempty"`
}
type Handler interface {
	Call(context.Context, *Request) (*Response, error)
}

func Register(s *grpc.Server, h Handler) {
	s.RegisterService(&grpc.ServiceDesc{ServiceName: "demo.Crypto", HandlerType: (*Handler)(nil), Methods: []grpc.MethodDesc{{MethodName: "Call", Handler: func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
		req := new(Request)
		if err := dec(req); err != nil {
			return nil, err
		}
		if interceptor == nil {
			return h.Call(ctx, req)
		}
		info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/demo.Crypto/Call"}
		return interceptor(ctx, req, info, func(c context.Context, r any) (any, error) { return h.Call(c, r.(*Request)) })
	}}}}, h)
}
func Invoke(ctx context.Context, c grpc.ClientConnInterface, op string, req *Request, out any) error {
	r := &Request{Target: op, Payload: req.Payload}
	resp := new(Response)
	if e := c.Invoke(ctx, "/demo.Crypto/Call", r, resp); e != nil {
		return e
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	return json.Unmarshal(resp.Payload, out)
}
