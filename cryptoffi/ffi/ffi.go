package ffi

import (
	"crypto/sha256"
)

func TrustedHash(data string) string {
	h := sha256.Sum256([]byte(data))
	return string(h[:])
}
