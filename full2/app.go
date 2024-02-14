package full2

import (
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/secure-chat/full2/fc_ffi_shim"
	"github.com/mit-pdos/secure-chat/full2/shared"
	"github.com/tchajed/goose/machine"
)

type Alice struct {
	ck    *Clerk
	a_msg *shared.MsgT
	b_msg *shared.MsgT
}

func (a *Alice) One() {
	a.ck.Put(a.a_msg)
}

func (a *Alice) Two() *shared.MsgT {
	g, err := a.ck.Get()
	machine.Assume(err == shared.ErrNone)
	if 2 <= len(g) {
		machine.Assert(g[0].Body == a.a_msg.Body)
		machine.Assert(g[1].Body == a.b_msg.Body)
		machine.Assert(len(g) == 2)

		g2, err := a.ck.Get()
		machine.Assume(err == shared.ErrNone)
		machine.Assert(g2[0].Body == a.a_msg.Body)
		machine.Assert(g2[1].Body == a.b_msg.Body)
		machine.Assert(len(g2) == 2)
		return g[0]
	}
	return nil
}

func MakeAlice(host grove_ffi.Address, signer *fc_ffi_shim.SignerT, verifiers []*fc_ffi_shim.VerifierT) *Alice {
	a := &Alice{}
	a.ck = MakeClerk(host, shared.AliceNum, signer, verifiers)
	a.a_msg = &shared.MsgT{Body: shared.AliceMsg}
	a.b_msg = &shared.MsgT{Body: shared.BobMsg}
	return a
}

type Bob struct {
	ck    *Clerk
	a_msg *shared.MsgT
	b_msg *shared.MsgT
}

func (b *Bob) One() *shared.MsgT {
	g, err := b.ck.Get()
	machine.Assume(err == shared.ErrNone)
	if 1 <= len(g) {
		machine.Assert(g[0].Body == b.a_msg.Body)
		machine.Assert(len(g) == 1)
		b.ck.Put(b.b_msg)
		return g[0]
	}
	return nil
}

func MakeBob(host grove_ffi.Address, signer *fc_ffi_shim.SignerT, verifiers []*fc_ffi_shim.VerifierT) *Bob {
	b := &Bob{}
	b.ck = MakeClerk(host, shared.BobNum, signer, verifiers)
	b.a_msg = &shared.MsgT{Body: shared.AliceMsg}
	b.b_msg = &shared.MsgT{Body: shared.BobMsg}
	return b
}
