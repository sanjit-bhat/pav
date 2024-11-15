package cryptoffi

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"github.com/google/keytransparency/core/crypto/vrf"
	"github.com/google/keytransparency/core/crypto/vrf/p256"
	"log"
)

const (
	HashLen uint64 = 32
)

// # Hash

func Hash(data []byte) []byte {
	h := sha512.Sum512_256(data)
	return h[:]
}

// # Signature

// SigPrivateKey has an unexported sk, which can't be accessed outside
// the package, without reflection or unsafe.
type SigPrivateKey struct {
	sk ed25519.PrivateKey
}

type SigPublicKey ed25519.PublicKey

func SigGenerateKey() (SigPublicKey, *SigPrivateKey) {
	pk, sk, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	return SigPublicKey(pk), &SigPrivateKey{sk: sk}
}

func (sk *SigPrivateKey) Sign(message []byte) []byte {
	return ed25519.Sign(ed25519.PrivateKey(sk.sk), message)
}

// Verify rets okay if proof verifies.
func (pk SigPublicKey) Verify(message []byte, sig []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(pk), message, sig)
}

// # VRF

// VrfPrivateKey has an unexported sk, which can't be accessed outside
// the package, without reflection or unsafe.
type VrfPrivateKey struct {
	sk vrf.PrivateKey
}

type VrfPublicKey struct {
	pk vrf.PublicKey
}

func VrfGenerateKey() (*VrfPublicKey, *VrfPrivateKey) {
	sk, pk := p256.GenerateKey()
	return &VrfPublicKey{pk: pk}, &VrfPrivateKey{sk: sk}
}

// TODO: check that Google CT's VRF satisfies all the properties we need.
// maybe re-write to use sha256 and the more robust [internal ed25519].
// [internal ed25519]: https://pkg.go.dev/filippo.io/edwards25519
func (sk *VrfPrivateKey) Hash(data []byte) ([]byte, []byte) {
	h, proof := sk.sk.Evaluate(data)
	// TODO: check that proof doesn't have h inside it.
	// that'd be a waste of space.
	return h[:], proof
}

// Verify rets okay if proof verifies.
func (pk *VrfPublicKey) Verify(data, hash, proof []byte) bool {
	h, err := pk.pk.ProofToHash(data, proof)
	if err != nil {
		return false
	}
	return bytes.Equal(hash, h[:])
}

// # Random

// RandBytes returns [n] random bytes.
func RandBytes(n uint64) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// don't care about recovering from crypto/rand failures.
	if err != nil {
		panic("crypto/rand call failed")
	}
	return b
}
