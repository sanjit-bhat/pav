package cryptoutil

import (
	"github.com/mit-pdos/pav/cryptoffi"
)

type Hasher = []byte

func HasherWrite(h *Hasher, data []byte) {
	*h = append(*h, data...)
}

func HasherWriteSl(h *Hasher, data [][]byte) {
	for _, hash := range data {
		HasherWrite(h, hash)
	}
}

func HasherSum(h Hasher, b []byte) []byte {
	hash := cryptoffi.Hash(h)
	var b1 = b
	b1 = append(b1, hash...)
	return b1
}
