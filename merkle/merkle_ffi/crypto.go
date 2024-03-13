package merkle_ffi

import (
	"github.com/zeebo/blake3"
)

func Hash(d []byte) []byte {
	h := blake3.New()
	h.Write(d)
	return h.Sum(nil)
}
