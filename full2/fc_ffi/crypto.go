package fc_ffi

import (
	"fmt"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/tink"
	"os"
)

type errorT = uint64

const (
	ErrNone errorT = 0
	ErrSome errorT = 1
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

func (c *CryptoT) MakeKeys() (*SignerT, *VerifierT, errorT) {
	f, err := os.Open(fmt.Sprintf("keys/priv%d.cfg", c.runs))
	if err != nil {
		return nil, nil, ErrSome
	}
	privKeys, err := insecurecleartextkeyset.Read(keyset.NewJSONReader(f))
	if err != nil {
		return nil, nil, ErrSome
	}
	s, err := signature.NewSigner(privKeys)
	if err != nil {
		return nil, nil, ErrSome
	}
	pubKeys, err := privKeys.Public()
	if err != nil {
		return nil, nil, ErrSome
	}
	v, err := signature.NewVerifier(pubKeys)
	if err != nil {
		return nil, nil, ErrSome
	}
	c.runs += 1
	return &SignerT{s}, &VerifierT{v}, ErrNone
}

func (s *SignerT) Sign(data []byte) ([]byte, errorT) {
	b, err := s.s.Sign(data)
	if err != nil {
		return nil, ErrSome
	}
	return b, ErrNone
}

func (v *VerifierT) Verify(signature, data []byte) errorT {
	if err := v.v.Verify(signature, data); err != nil {
		return ErrSome
	}
	return ErrNone
}
