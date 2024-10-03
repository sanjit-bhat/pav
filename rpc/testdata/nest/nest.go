package rpc

type inner struct {
	a1 uint64
}

type outer struct {
	a1 *inner
	a2 []*inner
	a3 map[uint64]*inner
}
