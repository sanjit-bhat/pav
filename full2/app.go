package full2

import (
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/secure-chat/full2/fc_ffi"
	"github.com/tchajed/goose/machine"
)

type Alice struct {
	ck    *Clerk
	a_msg *msgT
	b_msg *msgT
}

func (a *Alice) One() {
	a.ck.Put(a.a_msg)
}

func (a *Alice) Two() uint64 {
	g, err := a.ck.Get()
	machine.Assume(err == ErrNone)
	if 2 <= len(g) {
		machine.Assert(g[0].body == a.a_msg.body)
		machine.Assert(g[1].body == a.b_msg.body)
		machine.Assert(len(g) == 2)

		g2, err := a.ck.Get()
		machine.Assume(err == ErrNone)
		machine.Assert(g2[0].body == a.a_msg.body)
		machine.Assert(g2[1].body == a.b_msg.body)
		machine.Assert(len(g2) == 2)
		return g[0].body
	}
	return 0
}

func MakeAlice(host grove_ffi.Address, sk *fc_ffi.SignerT, pks []*fc_ffi.VerifierT) *Alice {
	a := &Alice{}
	a.ck = MakeClerk(host, AliceNum, sk, pks)
	a.a_msg = &msgT{body: AliceMsg}
	a.b_msg = &msgT{body: BobMsg}
	return a
}

type Bob struct {
	ck    *Clerk
	a_msg *msgT
	b_msg *msgT
}

func (b *Bob) One() uint64 {
	g, err := b.ck.Get()
	machine.Assume(err == ErrNone)
	if 1 <= len(g) {
		machine.Assert(g[0].body == b.a_msg.body)
		machine.Assert(len(g) == 1)
		b.ck.Put(b.b_msg)
		return g[0].body
	}
	return 0
}

func MakeBob(host grove_ffi.Address, sk *fc_ffi.SignerT, pks []*fc_ffi.VerifierT) *Bob {
	b := &Bob{}
	b.ck = MakeClerk(host, BobNum, sk, pks)
	b.a_msg = &msgT{body: AliceMsg}
	b.b_msg = &msgT{body: BobMsg}
	return b
}
