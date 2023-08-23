package chat4

type rpcIdT = uint64

const (
	RPCGET rpcIdT = 1
	RPCPUT rpcIdT = 2
)

// Don't have an err ret here bc semantics are to just fill "out" with "len(out)" arbitrary bytes.
func rpcCall(rpcId rpcIdT, in []byte, out []byte) {}

type signerT struct {
	key []byte
}

// Generate signature.
// The actual implementation would return an err if the signing key is invalid.
// The sig is SIG_LEN bytes.
func (s *signerT) sign(data []byte) ([]byte, errorT) {
	return make([]byte, SIG_LEN), ERRNONE
}

type verifierT struct {
	key []byte
}

// Verify a signature.
// The actual implementation would return an err if the verifier key is invalid
// or if the verification failed.
func (v *verifierT) verify(data []byte, sig []byte) errorT {
	return ERRNONE
}

// Arbitrarily made keys 64 bytes for now.
func makeKeys() (*signerT, *verifierT) {
	s := &signerT{key: make([]byte, 64)}
	v := &verifierT{key: make([]byte, 64)}
	return s, v
}
