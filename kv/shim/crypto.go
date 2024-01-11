package shim 

import (
	"github.com/mit-pdos/secure-chat/kv/shared"
)

type CryptoT struct {
}

func Init() *CryptoT {
    panic("ffi")
}

type SignerT struct{}

type VerifierT struct{}

func (c *CryptoT) MakeKeys() (*SignerT, *VerifierT, shared.ErrorT) {
    panic("ffi")
}

func (s *SignerT) Sign(data []byte) ([]byte, shared.ErrorT) {
    panic("ffi")
}

func (v *VerifierT) Verify(signature, data []byte) shared.ErrorT {
    panic("ffi")
}
