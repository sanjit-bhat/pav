package rpc

type args struct {
	// rpc: invariant: const true.
	a1 bool
	// rpc: invariant: const 3.
	a2 byte
	// rpc: invariant: const 3.
	a3 uint64
}
