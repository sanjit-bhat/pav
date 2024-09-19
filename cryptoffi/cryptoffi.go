package cryptoffi

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"github.com/google/keytransparency/core/crypto/vrf"
	"github.com/google/keytransparency/core/crypto/vrf/p256"
	"log"
)

type Sig = []byte

const (
	HashLen uint64 = 32
	SigLen  uint64 = 64
)

// Hash.

func Hash(data []byte) []byte {
	h := sha512.Sum512_256(data)
	return h[:]
}

// Signature.

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

// VRF.

type VRFPrivateKey struct {
	sk vrf.PrivateKey
}

type VRFPublicKey struct {
	pk vrf.PublicKey
}

func VRFGenerateKey() (*VRFPublicKey, *VRFPrivateKey) {
	sk, pk := p256.GenerateKey()
	return &VRFPublicKey{pk: pk}, &VRFPrivateKey{sk: sk}
}

func (priv VRFPrivateKey) Hash(data []byte) ([]byte, []byte) {
	h, proof := priv.sk.Evaluate(data)
	return h[:], proof
}

func (pub VRFPublicKey) Verify(data, hash, proof []byte) bool {
	h, err := pub.pk.ProofToHash(data, proof)
	if err != nil {
		return false
	}
	return bytes.Equal(hash, h[:])
}
