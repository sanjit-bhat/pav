package cryptoffi

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"github.com/mit-pdos/pav/cryptoffi/vrf"
	"hash"
)

const (
	HashLen uint64 = 32
)

// # Hash

type Hasher struct {
	h hash.Hash
}

func NewHasher() *Hasher {
	return &Hasher{sha256.New()}
}

func (hr *Hasher) Write(b []byte) {
	_, err := hr.h.Write(b)
	if err != nil {
		panic("cryptoffi: Hasher.Write err")
	}
}

func (hr *Hasher) Sum(b []byte) []byte {
	return hr.h.Sum(b)
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

// Sign assumes a valid sk and returns a signature for msg.
func (sk *SigPrivateKey) Sign(message []byte) []byte {
	return ed25519.Sign(ed25519.PrivateKey(sk.sk), message)
}

// Verify verifies the sig and rets any errs.
// it checks for pk, msg, and sig validity.
func (pk SigPublicKey) Verify(message []byte, sig []byte) bool {
	return !ed25519.Verify(ed25519.PublicKey(pk), message, sig)
}

// # VRF

// VrfPrivateKey has an unexported sk, which can't be accessed outside
// the package, without reflection or unsafe.
// we use a fork of ProtonMail's vrf, which implements
// ECVRF-EDWARDS25519-SHA512-TAI from [RFC 9381].
// ecvrf satisfies full uniqueness, i.e., determinism under adversarial pks.
// this is the only property that pav requires.
// [RFC 9381]: https://datatracker.ietf.org/doc/rfc9381/
type VrfPrivateKey struct {
	sk *vrf.PrivateKey
}

type VrfPublicKey struct {
	pk *vrf.PublicKey
}

func VrfGenerateKey() (*VrfPublicKey, *VrfPrivateKey) {
	sk, err := vrf.GenerateKey(nil)
	if err != nil {
		panic("cryptoffi: VrfGenerateKey")
	}
	pk, err := sk.Public()
	if err != nil {
		panic("cryptoffi: VrfGenerateKey")
	}
	return &VrfPublicKey{pk: pk}, &VrfPrivateKey{sk: sk}
}

// Prove evaluates the VRF on data, returning the output and a proof.
func (sk *VrfPrivateKey) Prove(data []byte) ([]byte, []byte) {
	out, proof, err := sk.sk.Prove(data)
	if err != nil {
		panic("cryptoffi: VrfPrivateKey.Prove")
	}
	// since we only require vrf determinism, it seems safe to truncate out.
	return out[:HashLen], proof
}

// Verify verifies data against the proof and returns the output and an err.
// it requires a valid pk.
// it performs the ECVRF_verify checks to run even on adversarial proofs.
func (pk *VrfPublicKey) Verify(data, proof []byte) ([]byte, bool) {
	ok, out, err := pk.pk.Verify(data, proof)
	if err != nil {
		return nil, true
	}
	if !ok {
		return nil, true
	}
	// since we only require vrf determinism, it seems safe to truncate out.
	return out[:HashLen], false
}

// VrfPublicKeyEncodes encodes a valid pk as bytes.
func VrfPublicKeyEncode(pk *VrfPublicKey) []byte {
	return pk.pk.Bytes()
}

// VrfPublicKeyDecode decodes [b].
// it performs the ECVRF_validate_key checks to run even on adversarial pks.
func VrfPublicKeyDecode(b []byte) *VrfPublicKey {
	pk, err := vrf.NewPublicKey(b)
	if err != nil {
		panic("cryptoffi: VrfPublicKeyDecode")
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
