package ktMerkle

import (
	"github.com/mit-pdos/secure-chat/crypto/shim"
	"github.com/tchajed/marshal"
)

type Epoch = uint64
type Link = []byte
type Error = uint64

const (
	// Errors
	ErrNone Error = 0
	ErrSome Error = 1
)

func CopySlice(b1 []byte) []byte {
	b2 := make([]byte, len(b1))
	copy(b2, b1)
	return b2
}

type EpochHash struct {
	Epoch uint64
	Hash  []byte
}

func (o *EpochHash) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.Epoch)
	b = marshal.WriteBytes(b, o.Hash)
	return b
}

func (o *EpochHash) Decode(b []byte) ([]byte, Error) {
	if uint64(len(b)) < 8 {
		return nil, ErrSome
	}
	epoch, b := marshal.ReadInt(b)
	if uint64(len(b)) < shim.HashLen {
		return nil, ErrSome
	}
	hash, b := marshal.ReadBytes(b, shim.HashLen)
	o.Epoch = epoch
	o.Hash = hash
	return b, ErrNone
}
