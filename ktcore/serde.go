package ktcore

const (
	VrfSigTag  byte = 1
	LinkSigTag byte = 2
)

type VrfSig struct {
	SigTag byte
	VrfPk  []byte
}

type LinkSig struct {
	SigTag byte
	Epoch  uint64
	Link   []byte
}

type MapLabel struct {
	Uid uint64
	Ver uint64
}

type CommitOpen struct {
	Val  []byte
	Rand []byte
}

type Memb struct {
	LabelProof  []byte
	PkOpen      *CommitOpen
	MerkleProof []byte
}

type NonMemb struct {
	LabelProof  []byte
	MerkleProof []byte
}

type AuditProof struct {
	Updates []*UpdateProof
	LinkSig []byte
}

type UpdateProof struct {
	MapLabel     []byte
	MapVal       []byte
	NonMembProof []byte
}
