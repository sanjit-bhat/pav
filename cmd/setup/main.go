package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"log"
	"os"
	"path"
)

func main() {
	keyDir := "keys"
	pubDir := path.Join(keyDir, "pub")
	privDir := path.Join(keyDir, "priv")
	if err := os.MkdirAll(pubDir, 0700); err != nil {
		log.Fatalln(err)
	}
	if err := os.MkdirAll(privDir, 0700); err != nil {
		log.Fatalln(err)
	}

	names := []string{"alice", "bob", "charlie", "danny", "eve"}
	for _, name := range names {
		priv, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			log.Fatalln(err)
		}
		pub := &priv.PublicKey
		pubB := x509.MarshalPKCS1PublicKey(pub)
		privB := x509.MarshalPKCS1PrivateKey(priv)
		if err := os.WriteFile(path.Join(pubDir, name), pubB, 0600); err != nil {
			log.Fatalln(err)
		}
		if err := os.WriteFile(path.Join(privDir, name), privB, 0600); err != nil {
			log.Fatalln(err)
		}
	}
}
