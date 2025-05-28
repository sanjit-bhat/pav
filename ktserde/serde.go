package ktserde

type PreSigDig struct {
	Epoch uint64
	Dig   []byte
}

type SigDig struct {
	Epoch uint64
	Dig   []byte
	Sig   []byte
}

type MapLabelPre struct {
	Uid uint64
	Ver uint64
}

type CommitOpen struct {
	Val  []byte
	Rand []byte
}

type MapValPre struct {
	Epoch    uint64
	PkCommit []byte
}

type Memb struct {
	LabelProof  []byte
	EpochAdded  uint64
	PkOpen      *CommitOpen
	MerkleProof []byte
}

type MembHide struct {
	LabelProof  []byte
	MapVal      []byte
	MerkleProof []byte
}

type NonMemb struct {
	LabelProof  []byte
	MerkleProof []byte
}

type UpdateProof struct {
	Updates map[string][]byte
	Sig     []byte
}
