package full2

import (
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/gokv/urpc"
	"github.com/tchajed/goose/machine"
)

type Clerk struct {
	cli *urpc.Client
}

func (c *Clerk) Put(m *msgT) {
	var reply []byte
	err := c.cli.Call(rpcPut, encodeMsgT(m), &reply, 100)
	machine.Assume(err == urpc.ErrNone)
}

func (c *Clerk) Get() []*msgT {
	var reply []byte
	err := c.cli.Call(rpcGet, make([]byte, 0), &reply, 100)
	machine.Assume(err == urpc.ErrNone)
	sl, _ := decodeSliceMsgT(reply)
	return sl
}

func MakeClerk(host grove_ffi.Address) *Clerk {
	c := &Clerk{}
	c.cli = urpc.MakeClient(host)
	return c
}
