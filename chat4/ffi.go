package chat4

type rpcIdT = uint64

const (
	RPCGET rpcIdT = 1
	RPCPUT rpcIdT = 2
)

// Don't have an err ret here bc semantics are to just return junk anyways.
func rpcCall(rpcId rpcIdT, in []byte, out []byte) {}


