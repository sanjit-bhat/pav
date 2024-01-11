package kv

import (
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/secure-chat/kv/ffi"
	"github.com/mit-pdos/secure-chat/kv/shared"
)

type KvCli struct {
	fc      *FcCli
	kv      map[uint64]uint64
	logNext uint64
}

func (c *KvCli) Put(k, v uint64) {
	m := shared.NewMsgT(0, k, v)
	log := c.fc.Put(m)
	c.injest(log)
}

func (c *KvCli) Get(k uint64) uint64 {
	log := c.fc.Get()
	c.injest(log)
	return c.kv[k]
}

func (c *KvCli) injest(log []*shared.MsgT) {
	for ; c.logNext < uint64(len(log)); c.logNext++ {
		m := log[c.logNext]
		if m.Op == shared.OpPut {
			c.kv[m.K] = m.V
		}
	}
}

func MakeKvCli(host grove_ffi.Address, signer *ffi.SignerT, verifiers []*ffi.VerifierT, myNum uint64) *KvCli {
	c := &KvCli{}
	c.fc = MakeFcCli(host, myNum, signer, verifiers)
	c.kv = make(map[uint64]uint64)
	return c
}
