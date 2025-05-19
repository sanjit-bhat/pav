package kt

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

type Memb struct {
	LabelProof  []byte
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

type ServerPutArg struct {
	Uid uint64
	Pk  []byte
}

type ServerPutReply struct {
	Dig    *SigDig
	Latest *Memb
	Bound  *NonMemb
	Err    bool
}

type ServerGetArg struct {
	Uid uint64
}

type ServerGetReply struct {
	Dig    *SigDig
	Hist   []*MembHide
	IsReg  bool
	Latest *Memb
	Bound  *NonMemb
}

type ServerSelfMonArg struct {
	Uid uint64
}

type ServerSelfMonReply struct {
	Dig   *SigDig
	Bound *NonMemb
}

type ServerAuditArg struct {
	Epoch uint64
}

type UpdateProof struct {
	Updates map[string][]byte
	Sig     []byte
}

type ServerAuditReply struct {
	P   *UpdateProof
	Err bool
}

type AdtrUpdateArg struct {
	P *UpdateProof
}

type AdtrUpdateReply struct {
	Err bool
}

type AdtrGetArg struct {
	Epoch uint64
}

type AdtrEpochInfo struct {
	Dig     []byte
	ServSig []byte
	AdtrSig []byte
}

type AdtrGetReply struct {
	X   *AdtrEpochInfo
	Err bool
}
