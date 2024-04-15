package cryptoFFI

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
	sk, vk := MakeKeys()
	sig := Sign(sk, d)
	if !Verify(vk, d, sig) {
		t.Fatal()
	}
}

func TestVerifyFalse(t *testing.T) {
	d1 := []byte("d1")
	d2 := []byte("d2")
	sk, vk := MakeKeys()
	sig := Sign(sk, d1)
	if Verify(vk, d2, sig) {
		t.Fatal()
	}
}
