package cryptoutil

import (
	"github.com/sanjit-bhat/pav/cryptoffi"
)

func Hash(b []byte) []byte {
	hr := cryptoffi.NewHasher()
	hr.Write(b)
	return hr.Sum(nil)
}
