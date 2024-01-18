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
	log       *shared.Log
	myNum     uint64
	signer    *ffi.SignerT
	verifiers []*ffi.VerifierT
}

func (c *FcCli) Put(data []byte) [][]byte {
	l := &shared.LogEntry{Op: shared.OpPut, Data: data}
	return c.prepareCommit(l)
}

func (c *FcCli) Get() [][]byte {
	empty := make([]byte, 0)
	l := &shared.LogEntry{Op: shared.OpGet, Data: empty}
	return c.prepareCommit(l)
}

func (c *FcCli) prepareCommit(e *shared.LogEntry) [][]byte {
	c.prepare()
	c.commit(e)
	logB := c.log.GetData()
	return logB
}

func (c *FcCli) prepare() {
	r := make([]byte, 0)
	err1 := c.urpc.Call(shared.RpcPrepare, make([]byte, 0), &r, 100)
	machine.Assume(err1 == urpc.ErrNone)

	if len(r) == 0 {
		// Init system with empty log.
		machine.Assume(len(c.log.Log) == 0)
		return
	}

	sLog := &shared.SignedLog{}
	err2 := sLog.Decode(r)
	machine.Assume(err2 == shared.ErrNone)

	pk := c.verifiers[sLog.Sender]
	log := sLog.Log
	logB := log.Encode()
	err3 := pk.Verify(sLog.Sig, logB)
	machine.Assume(err3 == shared.ErrNone)

	isPrefix := c.log.IsPrefix(log)
	machine.Assume(isPrefix)

	c.log = log
}

func (c *FcCli) commit(e *shared.LogEntry) {
	newLog := &shared.Log{Log: append(c.log.Log, e)}
	newLogB := newLog.Encode()

	sig, err1 := c.signer.Sign(newLogB)
	machine.Assume(err1 == shared.ErrNone)

	sLog := &shared.SignedLog{Sender: c.myNum, Sig: sig, Log: newLog}
	sLogB := sLog.Encode()

	r := make([]byte, 0)
	err2 := c.urpc.Call(shared.RpcCommit, sLogB, &r, 100)
	machine.Assume(err2 == urpc.ErrNone)
	c.log = newLog
}

func MakeFcCli(host grove_ffi.Address, myNum uint64, signer *ffi.SignerT, verifiers []*ffi.VerifierT) *FcCli {
	c := &FcCli{}
	c.urpc = urpc.MakeClient(host)
	empty := make([]*shared.LogEntry, 0)
	c.log = &shared.Log{Log: empty}
	c.myNum = myNum
	c.signer = signer
	c.verifiers = verifiers
	return c
}
