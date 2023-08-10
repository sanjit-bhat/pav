package ffi

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"os"
)

type Verifier struct {
	key *rsa.PublicKey
}

func NewVerifier(name string) (*Verifier, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS1PublicKey(b)
	if err != nil {
		return nil, err
	}
	return &Verifier{key: k}, nil
}

func (v *Verifier) Verify(msg []byte, sig []byte) error {
	h := Hash(msg)
	if err := rsa.VerifyPSS(v.key, crypto.SHA512, h, sig, nil); err != nil {
		return err
	}
	return nil
}
