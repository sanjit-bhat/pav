package rpc

type args struct {
	a1 bool
	a2 byte
	a3 uint64
	a4 []byte
	// rpc: invariant: len 16.
	a5 []byte
	a6 [][]byte
	a7 [][][]byte
}
