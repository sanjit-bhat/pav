package kt_shim

import (
	"github.com/mit-pdos/secure-chat/kt/shared"
)

type SignerT struct{}

type VerifierT struct{}

func MakeKeys() (*SignerT, *VerifierT) {
	panic("ffi")
}

func (s *SignerT) Sign(data []byte) []byte {
	panic("ffi")
}

func (v *VerifierT) Verify(signature, data []byte) shared.ErrorT {
	panic("ffi")
}
