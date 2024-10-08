package advrpc

import (
	"github.com/mit-pdos/pav/marshalutil"
	"github.com/tchajed/marshal"
	"math/rand/v2"
	"testing"
)

type Args struct {
	A, B uint64
}

func Multiply(args *Args) uint64 {
	return args.A * args.B
}

func encArgs(args *Args) []byte {
	var b0 []byte
	b1 := marshal.WriteInt(b0, args.A)
	b2 := marshal.WriteInt(b1, args.B)
	return b2
}

func decArgs(args []byte) (*Args, bool) {
	a, args0, err0 := marshalutil.ReadInt(args)
	if err0 {
		return nil, true
	}
	b, args1, err1 := marshalutil.ReadInt(args0)
	if err1 || len(args1) != 0 {
		return nil, true
	}
	return &Args{A: a, B: b}, false
}

func encReply(reply uint64) []byte {
	var b0 []byte
	return marshal.WriteInt(b0, reply)
}

func decReply(reply *[]byte) (uint64, bool) {
	if reply == nil {
		return 0, true
	}
	out, reply0, err0 := marshalutil.ReadInt(*reply)
	if err0 || len(reply0) != 0 {
		return 0, true
	}
	return out, false
}

func servStub(args []byte, reply *[]byte) {
	args0, err0 := decArgs(args)
	if err0 {
		*reply = nil
	}
	*reply = encReply(Multiply(args0))
}

func TestRPC(t *testing.T) {
	h := map[uint64]func([]byte, *[]byte){
		2: servStub,
	}
	s := NewServer(h)
	addr := makeUniqueAddr()
	s.Serve(addr)

	c := Dial(addr)
	args0 := &Args{A: 7, B: 8}
	args1 := encArgs(args0)
	reply0 := new([]byte)
	err1 := c.Call(2, args1, reply0)
	if err1 {
		t.Fatal()
	}

	reply1, err2 := decReply(reply0)
	if err2 {
		t.Fatal()
	}
	if reply1 != 7*8 {
		t.Fatal()
	}
}

func makeUniqueAddr() uint64 {
	port := uint64(rand.IntN(4000)) + 6000
	// left shift to make IP 0.0.0.0.
	return port << 32
}
