package cryptoutil

import (
	"github.com/mit-pdos/pav/cryptoffi"
)

func Hash(b []byte) []byte {
	hr := cryptoffi.NewHasher()
	hr.Write(b)
	return hr.Sum(nil)
}
