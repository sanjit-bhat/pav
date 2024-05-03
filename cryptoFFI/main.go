package cryptoFFI

import (
	"crypto/ed25519"
	"crypto/sha512"
	"log"
)

type Sig = []byte

const (
	HashLen uint64 = 32
	SigLen  uint64 = 64
)

// Hashing.

func Hash(data []byte) []byte {
	h := sha512.Sum512_256(data)
	return h[:]
}

// Signatures.

type PrivateKey = ed25519.PrivateKey

type PublicKey = ed25519.PublicKey

func MakeKeys() (PrivateKey, PublicKey) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	return PrivateKey(priv), PublicKey(pub)
}

func Sign(sk PrivateKey, data []byte) Sig {
	return ed25519.Sign(sk, data)
}

func Verify(pk PublicKey, data, sig Sig) bool {
	return ed25519.Verify(pk, data, sig)
}
