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
// The sig is 64 bytes.
func (s *signerT) sign(data []byte) ([]byte, errorT) {
	return make([]byte, 64), ERRNONE
}

type verifierT struct {
	key []byte
}

// Verify a signature.
// The actual implementation would return an err if the verifier key is invalid.
func (v *verifierT) verify(data []byte, sig []byte) bool {
	return true
}

func makeKeys() (*signerT, *verifierT) {
	s := &signerT{key: make([]byte, 64)}
	v := &verifierT{key: make([]byte, 64)}
	return s, v
}
