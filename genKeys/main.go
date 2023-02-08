package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"

	pb "example.com/chatGrpc"
	"google.golang.org/protobuf/proto"
)

func main() {
	names := []string{"alice", "bob", "charlie", "danny", "eve"}
	userKeys := make([]*pb.UserKey, 5)

	for idx := range userKeys {
		privKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			fmt.Println("failed rsa key gen:", err)
			return
		}
		pubKey := &privKey.PublicKey

		privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
		pubKeyBytes := x509.MarshalPKCS1PublicKey(pubKey)

		userKey := &pb.UserKey{Name: names[idx], PrivKey: privKeyBytes, PubKey: pubKeyBytes}
		userKeys[idx] = userKey
	}

	manyUserKeys := &pb.ManyUserKeys{UserKeys: userKeys}
	toDisk, err := proto.Marshal(manyUserKeys)
	if err != nil {
		fmt.Println("failed to marshal:", err)
		return
	}
	if err := os.WriteFile("demo_keys", toDisk, 0644); err != nil {
		fmt.Println("failed to write file:", err)
		return
	}
}
