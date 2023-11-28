package full2

import (
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/tchajed/goose/machine"
)

const aliceMsg uint64 = 10
const bobMsg uint64 = 11

type Alice struct {
	ck    *Clerk
	a_msg *msgT
	b_msg *msgT
}

func (a *Alice) One() {
	a.ck.Put(a.a_msg)
}

func (a *Alice) Two() uint64 {
	g := a.ck.Get()
	if 2 <= len(g) {
		machine.Assert(g[0].body == a.a_msg.body)
		machine.Assert(g[1].body == a.b_msg.body)
		machine.Assert(len(g) == 2)

		g2 := a.ck.Get()
		machine.Assert(g2[0].body == a.a_msg.body)
		machine.Assert(g2[1].body == a.b_msg.body)
		machine.Assert(len(g2) == 2)
		return g[0].body
	}
	return 0
}

func MakeAlice(host grove_ffi.Address) *Alice {
	a := &Alice{}
	a.ck = MakeClerk(host)
	a.a_msg = &msgT{body: aliceMsg}
	a.b_msg = &msgT{body: bobMsg}
	return a
}

type Bob struct {
	ck    *Clerk
	a_msg *msgT
	b_msg *msgT
}

func (b *Bob) One() uint64 {
	g := b.ck.Get()
	if 1 <= len(g) {
		machine.Assert(g[0].body == b.a_msg.body)
		machine.Assert(len(g) == 1)
		b.ck.Put(b.b_msg)
		return g[0].body
	}
	return 0
}

func MakeBob(host grove_ffi.Address) *Bob {
	b := &Bob{}
	b.ck = MakeClerk(host)
	b.a_msg = &msgT{body: aliceMsg}
	b.b_msg = &msgT{body: bobMsg}
	return b
}
