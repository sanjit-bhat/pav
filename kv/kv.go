package kv

import (
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/secure-chat/kv/shared"
	"github.com/mit-pdos/secure-chat/kv/shim"
)

type KvCli struct {
	fc      *FcCli
	kv      map[uint64]uint64
	logNext uint64
}

func (c *KvCli) Put(k, v uint64) shared.ErrorT {
	m := shared.NewMsgT(0, k, v)
	log, err := c.fc.Put(m)
	if err != shared.ErrNone {
		return err
	}
	c.injest(log)
	return shared.ErrNone
}

func (c *KvCli) Get(k uint64) shared.ErrorT {
	log, err := c.fc.Get()
	if err != shared.ErrNone {
		return err
	}
	c.injest(log)
	return shared.ErrNone
}

func (c *KvCli) injest(log []*shared.MsgT) {
	for ; c.logNext < uint64(len(log)); c.logNext++ {
		m := log[c.logNext]
		if m.Op == shared.OpPut {
			c.kv[m.K] = m.V
		}
	}
}

func MakeKvCli(host grove_ffi.Address, signer *shim.SignerT, verifiers []*shim.VerifierT, myNum uint64) *KvCli {
	c := &KvCli{}
	c.fc = MakeFcCli(host, myNum, signer, verifiers)
	return c
}
