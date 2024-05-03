package cryptoutil

import (
	"github.com/mit-pdos/secure-chat/cryptoffi"
)

type Hasher = []byte

// Goose doesn't support non-struct types that well, so until that exists,
// use type aliases and non-method funcs.
func HasherWrite(h *Hasher, data []byte) {
	for _, b := range data {
		*h = append(*h, b)
	}
}

func HasherWriteSl(h *Hasher, data [][]byte) {
	for _, hash := range data {
		HasherWrite(h, hash)
	}
}

func HasherSum(h Hasher, b []byte) []byte {
	var b1 = b
	hash := cryptoffi.Hash(h)
	for _, byt := range hash {
		b1 = append(b1, byt)
	}
	return b1
}
