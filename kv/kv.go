package kv

import (
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/secure-chat/kv/ffi"
	"github.com/mit-pdos/secure-chat/kv/shared"
)

// From the kv's standpoint, there is a log of only kv entries,
// not anything else added on by lower layers.

type KvCli struct {
	fc      *FcCli
	kv      map[uint64][]byte
	logNext uint64
}

func (c *KvCli) Put(k uint64, v []byte) {
	kv := &shared.KeyValue{K: k, V: v}
	kvB := kv.Encode()
	log := c.fc.Put(kvB)
	c.injest(log)
}

func (c *KvCli) Get(k uint64) []byte {
	log := c.fc.Get()
	c.injest(log)
	return c.kv[k]
}

func (c *KvCli) injest(log [][]byte) {
	for ; c.logNext < uint64(len(log)); c.logNext++ {
		kvB := log[c.logNext]
		kv := &shared.KeyValue{}
		kv.Decode(kvB)
		c.kv[kv.K] = kv.V
	}
}

func MakeKvCli(host grove_ffi.Address, signer *ffi.SignerT, verifiers []*ffi.VerifierT, myNum uint64) *KvCli {
	c := &KvCli{}
	c.fc = MakeFcCli(host, myNum, signer, verifiers)
	c.kv = make(map[uint64][]byte)
	return c
}
