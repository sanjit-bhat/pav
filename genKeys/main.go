package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"fmt"

	pb "example.com/chatGrpc"
	"google.golang.org/protobuf/proto"
)

func main() {
	origPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Println("failed rsa key gen:", err)
		return
	}
	_ = origPrivKey
	origPubKey := &origPrivKey.PublicKey
	_ = origPubKey

	privKeyBytes := x509.MarshalPKCS1PrivateKey(origPrivKey)
	pubKeyBytes := x509.MarshalPKCS1PublicKey(origPubKey)

	userKey := &pb.UserKey{Name: "alice", PrivKey: privKeyBytes, PubKey: pubKeyBytes}
	toDisk, err := proto.Marshal(userKey)
	if err != nil {
		fmt.Println("failed to marshal:", err)
		return
	}
	fromDisk := &pb.UserKey{}
	err = proto.Unmarshal(toDisk, fromDisk)
	if err != nil {
		fmt.Println("failed to unmarshal:", err)
		return
	}

	newPrivKey, err := x509.ParsePKCS1PrivateKey(fromDisk.GetPrivKey())
	_ = newPrivKey
	if err != nil {
		fmt.Println("failed to parse priv key:", err)
		return
	}
	newPubKey, err := x509.ParsePKCS1PublicKey(fromDisk.GetPubKey())
	_ = newPubKey
	if err != nil {
		fmt.Println("failed to parse pub key:", err)
		return
	}

	// CHANGE THESE
	expPrivKey := newPrivKey
	expPubKey := origPubKey

	hello := []byte("hello")
	helloEnc, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, expPubKey, hello, nil)
	if err != nil {
		fmt.Println("failed encrypt:", err)
		return
	}
	helloDec, err := rsa.DecryptOAEP(sha512.New(), rand.Reader, expPrivKey, helloEnc, nil)
	if err != nil {
		fmt.Println("failed decrypt:", err)
		return
	}
	if !bytes.Equal(hello, helloDec) {
		fmt.Println("failed dec same as orig msg")
		return
	}

	helloHash := sha512.Sum512(hello)
	sig, err := rsa.SignPSS(rand.Reader, expPrivKey, crypto.SHA512, helloHash[:], nil)
	if err != nil {
		fmt.Println("failed sig:", err)
		return
	}
	err = rsa.VerifyPSS(expPubKey, crypto.SHA512, helloHash[:], sig, nil)
	if err != nil {
		fmt.Println("failed verify:", err)
		return
	}
}
