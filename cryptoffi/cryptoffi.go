package cryptoffi

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

type PrivateKey ed25519.PrivateKey

type PublicKey ed25519.PublicKey

func GenerateKey() (PublicKey, PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	return PublicKey(pub), PrivateKey(priv)
}

func (priv PrivateKey) Sign(message []byte) Sig {
	return ed25519.Sign(ed25519.PrivateKey(priv), message)
}

func (pub PublicKey) Verify(message []byte, sig Sig) bool {
	return ed25519.Verify(ed25519.PublicKey(pub), message, sig)
}
