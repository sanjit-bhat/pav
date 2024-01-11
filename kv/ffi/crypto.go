package ffi

import (
	"fmt"
	"github.com/mit-pdos/secure-chat/kv/shared"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/tink"
	"os"
)

type CryptoT struct {
	runs uint64
}

func Init() *CryptoT {
	return &CryptoT{}
}

type SignerT struct {
	s tink.Signer
}

type VerifierT struct {
	v tink.Verifier
}

func (c *CryptoT) MakeKeys() (*SignerT, *VerifierT, shared.ErrorT) {
	f, err := os.Open(fmt.Sprintf("keys/priv%d.cfg", c.runs))
	if err != nil {
		return nil, nil, shared.ErrSome
	}
	privKeys, err := insecurecleartextkeyset.Read(keyset.NewJSONReader(f))
	if err != nil {
		return nil, nil, shared.ErrSome
	}
	s, err := signature.NewSigner(privKeys)
	if err != nil {
		return nil, nil, shared.ErrSome
	}
	pubKeys, err := privKeys.Public()
	if err != nil {
		return nil, nil, shared.ErrSome
	}
	v, err := signature.NewVerifier(pubKeys)
	if err != nil {
		return nil, nil, shared.ErrSome
	}
	c.runs += 1
	return &SignerT{s}, &VerifierT{v}, shared.ErrNone
}

func (s *SignerT) Sign(data []byte) ([]byte, shared.ErrorT) {
	b, err := s.s.Sign(data)
	if err != nil {
		return nil, shared.ErrSome
	}
	return b, shared.ErrNone
}

func (v *VerifierT) Verify(signature, data []byte) shared.ErrorT {
	if err := v.v.Verify(signature, data); err != nil {
		return shared.ErrSome
	}
	return shared.ErrNone
}
