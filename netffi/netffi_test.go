package netffi

import (
	"bytes"
	"math/rand/v2"
	"testing"
)

func TestNet(t *testing.T) {
	addr := makeUniqueAddr()
	l := Listen(addr)

	c0 := Dial(addr)
	d0 := []byte{1, 2}
	err1 := c0.Send(d0)
	if err1 {
		t.Fatal()
	}

	c1 := l.Accept()
	d1, err2 := c1.Receive()
	if err2 {
		t.Fatal()
	}
	if !bytes.Equal(d0, d1) {
		t.Fatal()
	}
}

func makeUniqueAddr() uint64 {
	port := uint64(rand.IntN(4000)) + 6000
	// left shift to make IP 0.0.0.0.
	return port << 32
}
