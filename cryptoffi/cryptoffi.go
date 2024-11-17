package cryptoffi

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"github.com/google/keytransparency/core/crypto/vrf"
	"github.com/google/keytransparency/core/crypto/vrf/p256"
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
		panic("cryptoffi: ed25519 keygen err")
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
// it uses Google KT's ecvrf under the hood, which satisfies [full uniqueness],
// i.e., determinism under adversarial pks.
// this is the only property that pav requires.
// [full uniqueness]: https://www.rfc-editor.org/rfc/rfc9381#name-elliptic-curve-vrf-ecvrf
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

// Hash computes the hash of data, along with a proof.
// TODO: rewrite to use ed25519 with the low-level [ed25519].
// [ed25519]: https://pkg.go.dev/filippo.io/edwards25519
func (sk *VrfPrivateKey) Hash(data []byte) ([]byte, []byte) {
	h, proof := sk.sk.Evaluate(data)
	return h[:], proof
}

// Verify verifies data against the proof and returns the hash and an err.
// it should perform the [ECVRF_verify] checks to run even on adversarial proofs.
// it can assume a valid pk.
// [ECVRF_verify]: https://www.rfc-editor.org/rfc/rfc9381#name-ecvrf-verifying
func (pk *VrfPublicKey) Verify(data, proof []byte) ([]byte, bool) {
	hash, err := pk.pk.ProofToHash(data, proof)
	if err != nil {
		return nil, true
	}
	return hash[:], false
}

// VrfPublicKeyEncodes encodes a valid pk as bytes.
func VrfPublicKeyEncode(pk *VrfPublicKey) []byte {
	pk2 := pk.pk.(*p256.PublicKey).PublicKey
	b, err := x509.MarshalPKIXPublicKey(pk2)
	if err != nil {
		panic("cryptoffi: vrf encoding err")
	}
	return b
}

// VrfPublicKeyDecode decodes [b].
// it should perform the [ECVRF_validate_key] checks to run even on adversarial pks.
// [ECVRF_validate_key]: https://www.rfc-editor.org/rfc/rfc9381#name-ecvrf-validate-key
func VrfPublicKeyDecode(b []byte) *VrfPublicKey {
	pk, err := p256.NewVRFVerifierFromRawKey(b)
	if err != nil {
		panic("cryptoffi: vrf decoding err")
	}
	return &VrfPublicKey{pk: pk}
}

// # Random

// RandBytes returns [n] random bytes.
func RandBytes(n uint64) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic("cryptoffi: crypto/rand err")
	}
	return b
}
