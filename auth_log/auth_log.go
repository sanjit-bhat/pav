package auth_log

type AuthLog struct {
}

func NewAuthLog() *AuthLog {
	return &AuthLog{}
}

type Entry struct {
}

type InclusionProof struct {
}

type ExtensionProof struct {
}

type EpochNum uint64

type Digest struct {
}

// Log API.

// InclusionProof should have latest merkle root,
// so caller can fast-forward itself.
func (l *AuthLog) Put(e *Entry) *InclusionProof {
	panic("todo")
}

// Assuming InclusionProof talks about id-value,
// so don't need to return that by itself.
func (l *AuthLog) Get(uname) *InclusionProof {
	panic("todo")
}

// Will special case certain values, e.g.,
// a 0 end might mean "up until latest epoch".
func (l *AuthLog) GetHist(uname, start, end EpochNum) []*InclusionProof {
	panic("todo")
}

// Not sure if this proof is really just list of inclusion proofs.
func (l *AuthLog) GetExtend(start, end EpochNum) *ExtensionProof {
	panic("todo")
}

// Authentication API.

func CheckInclusion(proof *InclusionProof) bool {
	panic("todo")
}

func CheckExtension(proof *ExtensionProof) bool {
    panic("todo")
}
