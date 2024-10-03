package main

type bello struct {
	a uint64
}

func (b *bello) call() uint64 {
	return 0
}

type hello struct {
	b *bello
}

func world() uint64 {
	h := &hello{}
	return h.b.call()
}

func Decode(b0 []byte) (*bello, []byte, bool) {
	return &bello{a: 1}, nil, false
}
