package cryptoffi

import (
	"bytes"
	"testing"
)

func TestHash(t *testing.T) {
	// same hashes for same input.
	d1 := []byte("d1")
	h1 := Hash(d1)
	h2 := Hash(d1)
	if !bytes.Equal(h1, h2) {
		t.Fatal()
	}
	if uint64(len(h1)) != HashLen {
		t.Fatal()
	}

	// diff hashes for diff inputs.
	d2 := []byte("d2")
	h3 := Hash(d2)
	if bytes.Equal(h1, h3) {
		t.Fatal()
	}
}

func TestSig(t *testing.T) {
	// verify true.
	d := []byte("d")
	pk, sk := SigGenerateKey()
	sig := sk.Sign(d)
	if !pk.Verify(d, sig) {
		t.Fatal()
	}

	// verify false for bad msg.
	if pk.Verify([]byte("d1"), sig) {
		t.Fatal()
	}

	// verify false for bad pk.
	pk2, _ := SigGenerateKey()
	if pk2.Verify(d, sig) {
		t.Fatal()
	}

	// verify false for bad sig.
	sig2 := bytes.Clone(sig)
	sig2[0] = ^sig2[0]
	if pk.Verify(d, sig2) {
		t.Fatal()
	}
}

func TestVRF(t *testing.T) {
	pk0, sk0 := VrfGenerateKey()

	// verify true.
	d0 := []byte("d0")
	h0, p := sk0.Hash(d0)
	h0Again, err := pk0.Verify(d0, p)
	if err {
		t.Fatal()
	}
	if !bytes.Equal(h0, h0Again) {
		t.Fatal()
	}

	// same hashes for same input.
	h1, _ := sk0.Hash(d0)
	if !bytes.Equal(h0, h1) {
		t.Fatal()
	}

	// diff hashes for diff inputs.
	d1 := []byte("d1")
	h2, _ := sk0.Hash(d1)
	if bytes.Equal(h0, h2) {
		t.Fatal()
	}

	// verify false for bad pk.
	pk1, _ := VrfGenerateKey()
	if _, err = pk1.Verify(d0, p); !err {
		t.Fatal()
	}

	// verify false for bad proof.
	p1 := bytes.Clone(p)
	p1[0] = ^p1[0]
	if _, err = pk0.Verify(d0, p1); !err {
		t.Fatal()
	}
}

func TestVRFSerde(t *testing.T) {
	pk0, sk := VrfGenerateKey()
	d := []byte("d")
	_, p := sk.Hash(d)

	pk0B := VrfPublicKeyEncode(pk0)
	pk1 := VrfPublicKeyDecode(pk0B)
	if _, err := pk1.Verify(d, p); err {
		t.Fatal()
	}
}
