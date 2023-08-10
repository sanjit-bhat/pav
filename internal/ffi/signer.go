package ffi

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"os"
)

type Signer struct {
	key *rsa.PrivateKey
}

func NewSigner(name string) (*Signer, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return nil, err
	}
	return &Signer{key: k}, nil
}

func (s *Signer) Sign(data []byte) ([]byte, error) {
	h := Hash(data)
	sig, err := rsa.SignPSS(rand.Reader, s.key, crypto.SHA512, h, nil)
	if err != nil {
		return nil, err
	}
	return sig, nil
}
