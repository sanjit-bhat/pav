package merkle

// MerkleProof defines a tree shell around an external label.
// the shell might have another leaf.
type MerkleProof struct {
	Siblings    []byte
	IsOtherLeaf bool
	LeafLabel   []byte
	LeafVal     []byte
}
