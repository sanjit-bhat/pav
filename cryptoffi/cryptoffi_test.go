package cryptoffi

import (
	"bytes"
	"testing"
)

func TestHashSame(t *testing.T) {
	d := []byte("d")
	h1 := Hash(d)
	h2 := Hash(d)
	if !bytes.Equal(h1, h2) {
		t.Fatal()
	}
	if uint64(len(h1)) != HashLen {
		t.Fatal()
	}
}

func TestHashDiff(t *testing.T) {
	d1 := []byte("d1")
	d2 := []byte("d2")
	h1 := Hash(d1)
	h2 := Hash(d2)
	if bytes.Equal(h1, h2) {
		t.Fatal()
	}
}

func TestVerifyTrue(t *testing.T) {
	d := []byte("d")
	pk, sk := GenerateKey()
	sig := sk.Sign(d)
	if !pk.Verify(d, sig) {
		t.Fatal()
	}
	if uint64(len(sig)) != SigLen {
		t.Fatal()
	}
}

func TestVerifyFalse(t *testing.T) {
	d1 := []byte("d1")
	d2 := []byte("d2")
	pk, sk := GenerateKey()
	sig := sk.Sign(d1)
	if pk.Verify(d2, sig) {
		t.Fatal()
	}
}

func TestVRF(t *testing.T) {
	pk0, sk0 := VRFGenerateKey()

	// check same hashes for same input.
	d0 := []byte("d0")
	h0, p0 := sk0.Hash(d0)
	if !pk0.Verify(d0, h0, p0) {
		t.Fatal()
	}
	h1, p1 := sk0.Hash(d0)
	if !pk0.Verify(d0, h1, p1) {
		t.Fatal()
	}
	if !bytes.Equal(h0, h1) {
		t.Fatal()
	}

	// check diff hashes for diff inputs.
	d1 := []byte("d1")
	h2, p2 := sk0.Hash(d1)
	if !pk0.Verify(d1, h2, p2) {
		t.Fatal()
	}
	if bytes.Equal(h0, h2) {
		t.Fatal()
	}

	// check verify false if use bad pk.
	pk1, _ := VRFGenerateKey()
	if pk1.Verify(d1, h2, p2) {
		t.Fatal()
	}

	// check verify false on bad proof.
	p3 := bytes.Clone(p2)
	p3[0] = ^p3[0]
	if pk0.Verify(d1, h2, p3) {
		t.Fatal()
	}
}
