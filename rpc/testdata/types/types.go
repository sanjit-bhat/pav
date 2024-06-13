package rpc

type args struct {
	a1 uint64
	a2 bool
	a3 []byte
	// rpc: invariant: len 16.
	a4 []byte
	a5 [][]byte
	a6 [][][]byte
	// rpc: invariant: const 3.
	a7 uint64
}
