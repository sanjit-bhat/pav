package merkle

// Proof has non-nil leaf data for non-membership proofs
// that terminate in a different leaf.
type MerkleProof struct {
	LeafLabel []byte
	LeafVal   []byte
	Siblings  []byte
}
