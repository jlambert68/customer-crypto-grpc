package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
)

var curve = elliptic.P256()
var order = curve.Params().N

type Point struct{ X, Y *big.Int }
type Envelope struct {
	R              Point
	Nonce, Wrapped []byte
}
type Object struct {
	ID                string
	Version           uint64
	Nonce, Ciphertext []byte
	Envelopes         map[string]Envelope
}
type Client struct {
	ID     string
	Secret *big.Int
	Public Point
}

func Scalar() (*big.Int, error) {
	n, e := rand.Int(rand.Reader, new(big.Int).Sub(order, big.NewInt(1)))
	if e != nil {
		return nil, e
	}
	return n.Add(n, big.NewInt(1)), nil
}
func Base(n *big.Int) Point {
	x, y := curve.ScalarBaseMult(n.FillBytes(make([]byte, 32)))
	return Point{x, y}
}
func Valid(p Point) bool { return p.X != nil && p.Y != nil && curve.IsOnCurve(p.X, p.Y) }
func Add(a, b Point) (Point, error) {
	if !Valid(a) || !Valid(b) {
		return Point{}, errors.New("invalid point")
	}
	x, y := curve.Add(a.X, a.Y, b.X, b.Y)
	if x == nil {
		return Point{}, errors.New("point at infinity")
	}
	return Point{x, y}, nil
}
func Mul(p Point, k *big.Int) (Point, error) {
	if !Valid(p) || k == nil || k.Sign() <= 0 || k.Cmp(order) >= 0 {
		return Point{}, errors.New("invalid point or scalar")
	}
	x, y := curve.ScalarMult(p.X, p.Y, k.FillBytes(make([]byte, 32)))
	if x == nil {
		return Point{}, errors.New("point at infinity")
	}
	return Point{x, y}, nil
}
func Random(n int) ([]byte, error) { b := make([]byte, n); _, e := rand.Read(b); return b, e }
func AAD(id string, v uint64, client string) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	h := sha256.New()
	h.Write([]byte("threshold-demo-v2"))
	for _, s := range []string{id, client} {
		l := make([]byte, 8)
		binary.BigEndian.PutUint64(l, uint64(len(s)))
		h.Write(l)
		h.Write([]byte(s))
	}
	h.Write(b)
	return h.Sum(nil)
}
func KDF(p Point, context []byte) []byte {
	ikm := elliptic.Marshal(curve, p.X, p.Y)
	ex := hmac.New(sha256.New, []byte("threshold-demo-v2-extract"))
	ex.Write(ikm)
	prk := ex.Sum(nil)
	expand := hmac.New(sha256.New, prk)
	expand.Write(context)
	expand.Write([]byte{1})
	return expand.Sum(nil)
}
func Seal(key, plain, ad []byte) ([]byte, []byte, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, nil, e
	}
	n, e := Random(g.NonceSize())
	if e != nil {
		return nil, nil, e
	}
	return n, g.Seal(nil, n, plain, ad), nil
}
func Open(key, nonce, ct, ad []byte) ([]byte, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	return g.Open(nil, nonce, ct, ad)
}
func NewClient(id string) (Client, error) {
	s, e := Scalar()
	if e != nil {
		return Client{}, e
	}
	return Client{id, s, Base(s)}, nil
}
func Encrypt(id string, version uint64, plain []byte, recipients map[string]Point) (Object, error) {
	dek, e := Random(32)
	if e != nil {
		return Object{}, e
	}
	n, ct, e := Seal(dek, plain, AAD(id, version, ""))
	if e != nil {
		return Object{}, e
	}
	o := Object{id, version, n, ct, map[string]Envelope{}}
	for cid, p := range recipients {
		r, e := Scalar()
		if e != nil {
			return Object{}, e
		}
		R := Base(r)
		shared, e := Mul(p, r)
		if e != nil {
			return Object{}, e
		}
		ad := AAD(id, version, cid)
		nn, wrapped, e := Seal(KDF(shared, ad), dek, ad)
		if e != nil {
			return Object{}, e
		}
		o.Envelopes[cid] = Envelope{R, nn, wrapped}
	}
	return o, nil
}
func Final(o Object, c Client, part Point) ([]byte, error) {
	env, ok := o.Envelopes[c.ID]
	if !ok {
		return nil, errors.New("missing envelope")
	}
	cp, e := Mul(env.R, c.Secret)
	if e != nil {
		return nil, e
	}
	shared, e := Add(cp, part)
	if e != nil {
		return nil, e
	}
	ad := AAD(o.ID, o.Version, c.ID)
	dek, e := Open(KDF(shared, ad), env.Nonce, env.Wrapped, ad)
	if e != nil {
		return nil, e
	}
	return Open(dek, o.Nonce, o.Ciphertext, AAD(o.ID, o.Version, ""))
}
