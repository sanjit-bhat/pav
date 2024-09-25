package rpcffi

import (
	"fmt"
	"github.com/mit-pdos/gokv/grove_ffi"
	"math/rand/v2"
	"testing"
)

type Args struct {
	A, B int
}

type Arith int

func (t *Arith) Multiply(args *Args, reply *int) error {
	*reply = args.A * args.B
	return nil
}

func TestRPC(t *testing.T) {
	port := rand.IntN(4000) + 6000
	ip := fmt.Sprintf("0.0.0.0:%d", port)
	addr := grove_ffi.MakeAddress(ip)

	if Serve(new(Arith), addr) {
		t.Fatal()
	}
	c, err := NewClient(addr)
	if err {
		t.Fatal()
	}

	args := &Args{7, 8}
	var reply int
	if c.Call("Arith.Multiply", args, &reply) {
		t.Fatal()
	}
	if args.A*args.B != reply {
		t.Fatal()
	}
}
