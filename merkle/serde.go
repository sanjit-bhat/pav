package merkle

// MerkleProof has non-nil leaf data for non-membership proofs
// that terminate in a different leaf.
type MerkleProof struct {
	Siblings       []byte
	FoundOtherLeaf bool
	LeafLabel      []byte
	LeafVal        []byte
}
