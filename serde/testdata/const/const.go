package serde

type args struct {
	// serde: invariant: const true.
	a1 bool
	// serde: invariant: const 3.
	a2 byte
	// serde: invariant: const 3.
	a3 uint64
}
