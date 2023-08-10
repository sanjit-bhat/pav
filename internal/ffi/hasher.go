package ffi

import (
	"crypto/sha512"
)

func Hash(data []byte) []byte {
	ha := sha512.Sum512(data)
	return ha[:]
}
