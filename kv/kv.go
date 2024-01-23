package kv

import (
	"fmt"
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/secure-chat/kv/ffi"
	"github.com/mit-pdos/secure-chat/kv/shared"
	"log/slog"
	"os"
	"time"
)

// From the kv's standpoint, there is a log of only kv entries,
// not anything else added on by lower layers.

type KvCli struct {
	fc      *FcCli
	kv      map[uint64][]byte
	logNext uint64
	logger  *slog.Logger
}

func (c *KvCli) Put(k uint64, v []byte) {
	kv := &shared.KeyValue{K: k, V: v}
	kvB := kv.Encode()
	start := time.Now()
	log := c.fc.Put(kvB)
	c.injest(log)
	end := time.Now()
	c.logger.Info("put", "key", k, "value", v, "start", start, "end", end)
}

func (c *KvCli) Get(k uint64) []byte {
	start := time.Now()
	log := c.fc.Get()
	c.injest(log)
	end := time.Now()
	ret := c.kv[k]
	c.logger.Info("get", "key", k, "value", ret, "start", start, "end", end)
	return ret
}

func (c *KvCli) injest(log [][]byte) {
	for ; c.logNext < uint64(len(log)); c.logNext++ {
		kvB := log[c.logNext]
		kv := &shared.KeyValue{}
		kv.Decode(kvB)
		c.kv[kv.K] = kv.V
	}
}

func MakeKvCli(host grove_ffi.Address, signer *ffi.SignerT, verifiers []*ffi.VerifierT, uid uint64) *KvCli {
	c := &KvCli{}
	c.fc = MakeFcCli(host, uid, signer, verifiers)
	c.kv = make(map[uint64][]byte)
	var err error
    f, err := os.Create(fmt.Sprintf("logs/cli%v.log", uid))
	if err != nil {
		panic(err)
	}
	c.logger = slog.New(slog.NewJSONHandler(f, nil)).With("cli", uid)
	return c
}
