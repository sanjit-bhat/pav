package auditor

import (
	"github.com/mit-pdos/pav/ktserde"
)

type AdtrUpdateArg struct {
	P *ktserde.UpdateProof
}

type AdtrUpdateReply struct {
	Err bool
}

type AdtrGetArg struct {
	Epoch uint64
}

type AdtrEpochInfo struct {
	Dig     []byte
	ServSig []byte
	AdtrSig []byte
}

type AdtrGetReply struct {
	X   *AdtrEpochInfo
	Err bool
}
