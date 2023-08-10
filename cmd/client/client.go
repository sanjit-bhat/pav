package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"path"
	"sync"

	"example.com/internal/ffi"
	pb "example.com/internal/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type seqNumT uint64
type msgsProt struct {
	mu   sync.Mutex
	data map[seqNumT]*pb.MsgWrap
}

type cancelProt struct {
	mu   sync.Mutex
	data context.CancelCauseFunc
	done bool
}

type unameT string
type client struct {
	rpc       pb.ChatClient
	name      string
	signer    *ffi.Signer
	verifiers map[unameT]*ffi.Verifier
	msgs      msgsProt
	cancel    cancelProt
}

func newClient() (*client, *grpc.ClientConn) {
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalln("failed to connect:", err)
	}
	c := &client{rpc: pb.NewChatClient(conn)}
	c.verifiers = make(map[unameT]*ffi.Verifier)
	c.msgs.data = make(map[seqNumT]*pb.MsgWrap)
	return c, conn
}

func getNames() []string {
	return []string{"alice", "bob", "charlie", "danny", "eve"}
}

func (c *client) loadKeys() error {
	keyDir := "keys"
	pubDir := path.Join(keyDir, "pub")
	privDir := path.Join(keyDir, "priv")

	privFile := path.Join(privDir, c.name)
	s, err := ffi.NewSigner(privFile)
	if err != nil {
		return err
	}
	c.signer = s

	for _, name := range getNames() {
		pubFile := path.Join(pubDir, name)
		v, err := ffi.NewVerifier(pubFile)
		if err != nil {
			return err
		}
		c.verifiers[unameT(name)] = v
	}
	return nil
}

var errUserEndClient = errors.New("user ended the client")

func (c *client) listMsgs() {
	c.msgs.mu.Lock()
	defer c.msgs.mu.Unlock()
	msgs := c.msgs.data
	for seqNum, m := range msgs {
		fmt.Printf("[%v] [%v]: \"%v\"\n", seqNum, m.Msg.Sender, m.Msg.Body)
	}
}

func (c *client) callCancel() {
	c.cancel.mu.Lock()
	defer c.cancel.mu.Unlock()
	if c.cancel.data != nil {
		c.cancel.data(errUserEndClient)
	} else {
		c.cancel.done = true
	}
}
