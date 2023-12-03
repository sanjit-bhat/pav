package full2

import (
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/secure-chat/full2/fc_ffi"
	"github.com/tchajed/goose/machine"
	"github.com/tchajed/marshal"
)

// Clerk only supports sequential calls to its methods.
type Clerk struct {
	cli     *urpc.Client
	log     []*msgT
	myNum   uint64
	privKey *fc_ffi.SignerT
	pubKeys []*fc_ffi.VerifierT
}

func (c *Clerk) Put(m *msgT) {
	log := append(c.log, m)
	logB := encodeMsgTSlice(log)
	sig, err := c.privKey.Sign(logB)
	// ECDSA_P256 gave diff len sigs, which complicates encoding.
	// ED25519 should have const len sigs.
	machine.Assume(uint64(len(sig)) == SigLen)
	machine.Assume(err == ErrNone)

	var b = make([]byte, 0)
	b = marshal.WriteInt(b, c.myNum)
	b = marshal.WriteBytes(b, sig)
	b = marshal.WriteBytes(b, logB)

	var r []byte
	err = c.cli.Call(RpcPut, b, &r, 100)
	machine.Assume(err == urpc.ErrNone)
}

func (c *Clerk) Get() ([]*msgT, errorT) {
	var r []byte
	err := c.cli.Call(RpcGet, make([]byte, 0), &r, 100)
	machine.Assume(err == urpc.ErrNone)

	if len(r) < 8 {
		return nil, ErrSome
	}
	sender, r2 := marshal.ReadInt(r)
	if !(0 <= sender && sender < MaxSenders) {
		return nil, ErrSome
	}
	if uint64(len(r2)) < SigLen {
		return nil, ErrSome
	}
	sig, data := marshal.ReadBytes(r2, SigLen)

	pk := c.pubKeys[sender]
	if pk.Verify(sig, data) != ErrNone {
		return nil, ErrSome
	}

	log, _ := decodeMsgTSlice(data)
	if !isMsgTPrefix(c.log, log) {
		return nil, ErrSome
	}
	c.log = log

	return log, ErrNone
}

func MakeClerk(host grove_ffi.Address, myNum uint64, privKey *fc_ffi.SignerT, pubKeys []*fc_ffi.VerifierT) *Clerk {
	c := &Clerk{}
	c.cli = urpc.MakeClient(host)
	c.log = make([]*msgT, 0)
	c.myNum = myNum
	c.privKey = privKey
	c.pubKeys = pubKeys
	return c
}
