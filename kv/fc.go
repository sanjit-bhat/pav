package kv

import (
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/secure-chat/kv/ffi"
	"github.com/mit-pdos/secure-chat/kv/shared"
	"github.com/tchajed/goose/machine"
)

// FcCli only supports sequential calls to its methods.
type FcCli struct {
	urpc      *urpc.Client
	log       []*shared.MsgT
	myNum     uint64
	signer    *ffi.SignerT
	verifiers []*ffi.VerifierT
}

func (c *FcCli) Put(m *shared.MsgT) []*shared.MsgT {
	// Copy bc I don't want to deal with caller ownership transfer.
	m2 := m.Copy()
	m2.Op = shared.OpPut
	return c.prepareCommit(m2)
}

func (c *FcCli) Get() []*shared.MsgT {
	m := shared.NewMsgT(shared.OpGet, 0, 0)
	return c.prepareCommit(m)
}

func (c *FcCli) prepareCommit(m *shared.MsgT) []*shared.MsgT {
	c.prepare()
	c.commit(m)
	log := shared.CopyMsgTSlice(c.log)
	return log
}

func (c *FcCli) prepare() {
	r := make([]byte, 0)
	err1 := c.urpc.Call(shared.RpcPrepare, make([]byte, 0), &r, 100)
	machine.Assume(err1 == urpc.ErrNone)

	if len(r) == 0 {
		// Init system with empty log.
		machine.Assume(len(c.log) == 0)
		return
	}

	arg, err2 := shared.DecodePutArg(r)
	machine.Assume(err2 == shared.ErrNone)

	pk := c.verifiers[arg.Sender]
	err3 := pk.Verify(arg.Sig, arg.LogB)
	machine.Assume(err3 == shared.ErrNone)

	log, _ := shared.DecodeMsgTSlice(arg.LogB)
	isPrefix := shared.IsMsgTSlicePrefix(c.log, log)
	machine.Assume(isPrefix)

	c.log = log
}

func (c *FcCli) commit(m *shared.MsgT) {
	log := shared.CopyMsgTSlice(c.log)
	log2 := append(log, m)
	log2B := shared.EncodeMsgTSlice(log2)

	sig, err1 := c.signer.Sign(log2B)
	machine.Assume(err1 == shared.ErrNone)

	pa := shared.NewPutArg(c.myNum, sig, log2B)
	argB := pa.Encode()

	r := make([]byte, 0)
	err2 := c.urpc.Call(shared.RpcCommit, argB, &r, 100)
	machine.Assume(err2 == urpc.ErrNone)
	c.log = log2
}

func MakeFcCli(host grove_ffi.Address, myNum uint64, signer *ffi.SignerT, verifiers []*ffi.VerifierT) *FcCli {
	c := &FcCli{}
	c.urpc = urpc.MakeClient(host)
	c.log = make([]*shared.MsgT, 0)
	c.myNum = myNum
	c.signer = signer
	c.verifiers = verifiers
	return c
}
