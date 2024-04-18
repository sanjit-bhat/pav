package ktMerkle

import (
	"github.com/mit-pdos/secure-chat/merkle"
)

type ErrorT = uint64

const (
	// Errors
	ErrNone ErrorT = 0
	ErrSome ErrorT = 1
)

func CopySlice(b1 []byte) []byte {
	b2 := make([]byte, len(b1))
	copy(b2, b1)
	return b2
}

type IdVal struct {
	Id  merkle.Id
	Val merkle.Val
}
