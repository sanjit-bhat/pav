package ffi

import (
	"fmt"
	"github.com/mit-pdos/secure-chat/kv/shared"
	"github.com/tchajed/goose/machine"
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

func (c *CryptoT) MakeKeys() (*SignerT, *VerifierT) {
	machine.Assert(c.runs < shared.MaxUsers)
	f, err := os.Open(fmt.Sprintf("../keys/priv%d.cfg", c.runs))
	machine.Assert(err == nil)
	privKeys, err := insecurecleartextkeyset.Read(keyset.NewJSONReader(f))
	machine.Assert(err == nil)
	s, err := signature.NewSigner(privKeys)
	machine.Assert(err == nil)
	pubKeys, err := privKeys.Public()
	machine.Assert(err == nil)
	v, err := signature.NewVerifier(pubKeys)
	machine.Assert(err == nil)
	c.runs += 1
	return &SignerT{s}, &VerifierT{v}
}

func (s *SignerT) Sign(data []byte) []byte {
	b, err := s.s.Sign(data)
	machine.Assert(err == nil)
	return b
}

func (v *VerifierT) Verify(signature, data []byte) shared.ErrorT {
	if err := v.v.Verify(signature, data); err != nil {
		return shared.ErrSome
	}
	return shared.ErrNone
}
