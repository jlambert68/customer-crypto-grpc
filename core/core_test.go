package core

import "testing"

func TestTwoSharesAndCrossClient(t *testing.T) {
	s1, _ := NewClient("s1")
	c1, _ := NewClient("c1")
	s2, _ := NewClient("s2")
	c2, _ := NewClient("c2")
	p1, _ := Add(s1.Public, c1.Public)
	p2, _ := Add(s2.Public, c2.Public)
	obj, e := Encrypt("C001", 1, []byte("secret"), map[string]Point{"c1": p1, "c2": p2})
	if e != nil {
		t.Fatal(e)
	}
	part1, e := Mul(obj.Envelopes["c1"].R, s1.Secret)
	if e != nil {
		t.Fatal(e)
	}
	got, e := Final(obj, c1, part1)
	if e != nil || string(got) != "secret" {
		t.Fatal(e)
	}
	part2, _ := Mul(obj.Envelopes["c2"].R, s2.Secret)
	got, e = Final(obj, c2, part2)
	if e != nil || string(got) != "secret" {
		t.Fatal(e)
	}
	obj.Envelopes["c2"] = obj.Envelopes["c1"]
	if _, e = Final(obj, c2, part1); e == nil {
		t.Fatal("cross client must fail")
	}
}
