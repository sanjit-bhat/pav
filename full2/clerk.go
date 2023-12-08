package full2

import (
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/secure-chat/full2/fc_ffi_shim"
	"github.com/mit-pdos/secure-chat/full2/shared"
	"github.com/tchajed/goose/machine"
)

// Clerk only supports sequential calls to its methods.
type Clerk struct {
	cli       *urpc.Client
	log       []*shared.MsgT
	myNum     uint64
	signer    *fc_ffi_shim.SignerT
	verifiers []*fc_ffi_shim.VerifierT
}

func (c *Clerk) Put(m *shared.MsgT) {
	m2 := m.Copy()
	log := make([]*shared.MsgT, len(c.log))
	copy(log, c.log)
	log2 := append(log, m2)
	log2B := shared.EncodeMsgTSlice(log2)

	sig, err1 := c.signer.Sign(log2B)
	machine.Assume(err1 == shared.ErrNone)

	pa := shared.NewPutArg(c.myNum, sig, log2B)
	argB := pa.Encode()
	r := make([]byte, 0)
	err2 := c.cli.Call(shared.RpcPut, argB, &r, 100)
	machine.Assume(err2 == urpc.ErrNone)
}

func (c *Clerk) Get() ([]*shared.MsgT, shared.ErrorT) {
	nilRet := make([]*shared.MsgT, 0)
	r := make([]byte, 0)
	err1 := c.cli.Call(shared.RpcGet, make([]byte, 0), &r, 100)
	if err1 != urpc.ErrNone {
		return nilRet, shared.ErrSome
	}

	arg, err2 := shared.DecodePutArg(r)
	if err2 != shared.ErrNone {
		return nilRet, shared.ErrSome
	}

	pk := c.verifiers[arg.Sender]
	err3 := pk.Verify(arg.Sig, arg.LogB)
	if err3 != shared.ErrNone {
		return nilRet, shared.ErrSome
	}

	log, _ := shared.DecodeMsgTSlice(arg.LogB)
	if !shared.IsMsgTSlicePrefix(c.log, log) {
		return nilRet, shared.ErrSome
	}
	c.log = shared.CopyMsgTSlice(log)

	return log, shared.ErrNone
}

func MakeClerk(host grove_ffi.Address, myNum uint64, signer *fc_ffi_shim.SignerT, verifiers []*fc_ffi_shim.VerifierT) *Clerk {
	c := &Clerk{}
	c.cli = urpc.MakeClient(host)
	c.log = make([]*shared.MsgT, 0)
	c.myNum = myNum
	c.signer = signer
	c.verifiers = verifiers
	return c
}
