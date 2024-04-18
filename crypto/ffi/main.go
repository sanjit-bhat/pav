package ffi

import (
	"crypto/ed25519"
	"crypto/sha512"
	"log"
)

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

type SignerT = ed25519.PrivateKey

type VerifierT = ed25519.PublicKey

func MakeKeys() (SignerT, VerifierT) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	return SignerT(priv), VerifierT(pub)
}

func Sign(sk SignerT, data []byte) []byte {
	return ed25519.Sign(sk, data)
}

func Verify(vk VerifierT, data, sig []byte) bool {
	return ed25519.Verify(vk, data, sig)
}
