package merkle

import "testing"

func TestRootOrderIndependent(t *testing.T) {
	a, b, c := Leaf("issued", "1"), Leaf("issued", "2"), Leaf("revoked", "1")
	r1 := Root([][32]byte{a, b, c})
	r2 := Root([][32]byte{c, a, b})
	if r1 != r2 {
		t.Fatal("root depends on input order")
	}
	if Root([][32]byte{a, b}) == r1 {
		t.Fatal("adding a leaf did not change the root")
	}
	if Root([][32]byte{a}) != a {
		t.Fatal("single-leaf root should be the leaf")
	}
}
