package kv

import (
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/secure-chat/kv/shared"
	"github.com/mit-pdos/secure-chat/kv/shim"
	"github.com/tchajed/goose/machine"
)

// FcCli only supports sequential calls to its methods.
type FcCli struct {
	urpc      *urpc.Client
	log       []*shared.MsgT
	myNum     uint64
	signer    *shim.SignerT
	verifiers []*shim.VerifierT
}

func (c *FcCli) Put(m *shared.MsgT) ([]*shared.MsgT, shared.ErrorT) {
	// Copy bc I don't want to deal with caller ownership transfer.
	m2 := m.Copy()
	m2.Op = shared.OpPut
	return c.prepareCommit(m2)
}

func (c *FcCli) Get() ([]*shared.MsgT, shared.ErrorT) {
	m := shared.NewMsgT(shared.OpGet, 0, 0)
	return c.prepareCommit(m)
}

func (c *FcCli) prepareCommit(m *shared.MsgT) ([]*shared.MsgT, shared.ErrorT) {
	nilRet := make([]*shared.MsgT, 0)
	err1 := c.prepare()
	if err1 != urpc.ErrNone {
		return nilRet, shared.ErrSome
	}
	c.commit(m)
	log := shared.CopyMsgTSlice(c.log)
	return log, shared.ErrNone
}

func (c *FcCli) prepare() shared.ErrorT {
	r := make([]byte, 0)
	err1 := c.urpc.Call(shared.RpcPrepare, make([]byte, 0), &r, 100)
	if err1 != urpc.ErrNone {
		return shared.ErrSome
	}

	arg, err2 := shared.DecodePutArg(r)
	if err2 != shared.ErrNone {
		return shared.ErrSome
	}

	pk := c.verifiers[arg.Sender]
	err3 := pk.Verify(arg.Sig, arg.LogB)
	if err3 != shared.ErrNone {
		return shared.ErrSome
	}

	log, _ := shared.DecodeMsgTSlice(arg.LogB)
	if !shared.IsMsgTSlicePrefix(c.log, log) {
		return shared.ErrSome
	}

	c.log = log
	return shared.ErrNone
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

func MakeFcCli(host grove_ffi.Address, myNum uint64, signer *shim.SignerT, verifiers []*shim.VerifierT) *FcCli {
	c := &FcCli{}
	c.urpc = urpc.MakeClient(host)
	c.log = make([]*shared.MsgT, 0)
	c.myNum = myNum
	c.signer = signer
	c.verifiers = verifiers
	return c
}
