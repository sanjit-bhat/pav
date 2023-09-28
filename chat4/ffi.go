package chat4

type rpcIdT = uint64

const (
	RPCGET rpcIdT = 1
	RPCPUT rpcIdT = 2
)

// Don't have an err ret here bc semantics are to just fill "out" with "len(out)" arbitrary bytes.
func rpcCall(rpcId rpcIdT, in []byte, out []byte) {}

// Arbitrarily made keys 64 bytes for now.
func makeKeys() (*signerT, []byte) {
	s := &signerT{key: make([]byte, 64)}
	return s, make([]byte, 64)
}

// Right now, Go's notion of private (non-exported)
// lower-case fields prevents the owner of signerT from
// accessing the underlying key.
type signerT struct {
	key []byte
}

// Generate signature.
// For now, sign is UB when you try to call it with an invalid signing key
// or an invalid predicate.
// The sig is SIG_LEN bytes.
func (s *signerT) sign(data []byte) []byte {
	return make([]byte, SIG_LEN)
}

// Verify a signature.
// The actual implementation would return an err if the
// verification key is invalid or if the verification failed.
func verify(vk []byte, data []byte, sig []byte) errorT {
	return ERRNONE
}
