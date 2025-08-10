package merkle

// MerkleProof helps Verify learn an entry in the map.
type MerkleProof struct {
	// Siblings provide a tree shell around an external label.
	Siblings []byte
	// IsOtherLeaf provides a different leaf down label,
	// for verifying non-membership.
	IsOtherLeaf bool
	LeafLabel   []byte
	LeafVal     []byte
}
