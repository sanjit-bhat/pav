package ffi

import (
	"github.com/mit-pdos/secure-chat/kt/shared"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/tink"
	"log"
)

type SignerT struct {
	s tink.Signer
}

type VerifierT struct {
	v tink.Verifier
}

func MakeKeys() (*SignerT, *VerifierT) {
	h, err := keyset.NewHandle(signature.ED25519KeyTemplate())
	if err != nil {
		log.Fatal(err)
	}
	s, err := signature.NewSigner(h)
	if err != nil {
		log.Fatal(err)
	}
	hPub, err := h.Public()
	if err != nil {
		log.Fatal(err)
	}
	v, err := signature.NewVerifier(hPub)
	if err != nil {
		log.Fatal(err)
	}
	return &SignerT{s}, &VerifierT{v}
}

func (s *SignerT) Sign(data []byte) []byte {
	b, err := s.s.Sign(data)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func (v *VerifierT) Verify(signature, data []byte) shared.ErrorT {
	if err := v.v.Verify(signature, data); err != nil {
		return shared.ErrVerify
	}
	return shared.ErrNone
}
