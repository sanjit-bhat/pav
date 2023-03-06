package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"os"
	"sync"
	"time"

	pb "example.com/chatGrpc"
	"github.com/manifoldco/promptui"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

type userMetadata struct {
	pubKey *rsa.PublicKey
}

type myMetadata struct {
	userMetadata
	name    string
	privKey *rsa.PrivateKey
}

type msgGuard struct {
	msg *pb.Msg
	mu  sync.Mutex
}

type client struct {
	rpc    pb.ChatClient
	myData *myMetadata
	// Key is the username.
	allData map[string]*userMetadata
	lastMsg msgGuard
}

func newClient() (*client, *grpc.ClientConn) {
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalln("failed to connect:", err)
	}
	c := &client{rpc: pb.NewChatClient(conn)}
	c.myData = &myMetadata{}
	c.allData = make(map[string]*userMetadata)
	return c, conn
}

func (myClient *client) runNameLoop() {
	for {
		prompt := promptui.Select{
			Label: "Name",
			Items: []string{"alice", "bob", "charlie", "danny", "eve"},
		}
		_, name, err := prompt.Run()
		if err != nil {
			log.Println("warning: failed prompt:", err)
			continue
		}
		myClient.myData.name = name
		return
	}
}

func (myClient *client) loadKeys() error {
	fileBytes, err := os.ReadFile("demo_keys")
	if err != nil {
		return err
	}
	manyUserKeys := &pb.ManyUserKeys{}
	if err := proto.Unmarshal(fileBytes, manyUserKeys); err != nil {
		return err
	}

	for _, userKey := range manyUserKeys.UserKeys {
		pubKey, err := x509.ParsePKCS1PublicKey(userKey.PubKey)
		if err != nil {
			return err
		}

		if myClient.myData.name == userKey.Name {
			privKey, err := x509.ParsePKCS1PrivateKey(userKey.PrivKey)
			if err != nil {
				return err
			}
			myClient.myData.privKey = privKey
			myClient.myData.pubKey = pubKey
		} else {
			user, ok := myClient.allData[userKey.Name]
			if !ok {
				user = &userMetadata{}
				myClient.allData[userKey.Name] = user
			}
			user.pubKey = pubKey
		}
	}

	if myClient.myData.privKey == nil {
		return errors.New("do not have private key for user")
	}
	return nil
}

func (myClient *client) compHash(msg proto.Message) ([]byte, error) {
	bytes, err := proto.Marshal(msg)
	if err != nil {
		return nil, err
	}
	hash := sha512.Sum512(bytes)
	return hash[:], nil
}

func (myClient *client) checkSig(msgHashSig *pb.MsgHashSig) error {
	msgHash, err := myClient.compHash(msgHashSig.MsgHash)
	if err != nil {
		return err
	}
	userData, ok := myClient.allData[msgHashSig.MsgHash.Msg.Sender]
	if !ok {
		return errors.New("do not have public key for user")
	}
	if err := rsa.VerifyPSS(userData.pubKey, crypto.SHA512, msgHash, msgHashSig.Sig, nil); err != nil {
		return err
	}
	return nil
}

func (myClient *client) tryAddNewMsg(msgHashSig *pb.MsgHashSig) error {
	// Check signature.
	if err := myClient.checkSig(msgHashSig); err != nil {
		return err
	}

	// Check hash chain.
	myClient.lastMsg.mu.Lock()
	defer myClient.lastMsg.mu.Unlock()
	hashComputed, err := myClient.compHash(myClient.lastMsg.msg)
	if err != nil {
		return err
	}
	if !bytes.Equal(hashComputed, msgHashSig.MsgHash.Hash) {
		return errors.New("hash chains are not equal")
	}

	msg := msgHashSig.MsgHash.Msg
	log.Printf("`%v`: \"%v\"\n", msg.Sender, msg.Text)
	myClient.lastMsg.msg = msg
	return nil
}

func (myClient *client) getMsgs() {
	// TODO: don't know how to do indefinite timeout, so use an hour instead.
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	stream, err := myClient.rpc.GetMsgs(ctx, &pb.GetMsgsReq{Sender: myClient.myData.name})
	if err != nil {
		log.Fatalln("failed getMsgs:", err)
	}

	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			return
		}
		if err != nil {
			log.Fatalln("failed getMsgs stream recv:", err)
		}
		if err = myClient.tryAddNewMsg(resp.MsgHashSig); err != nil {
			log.Println("failed to add msg:", err)
		}
	}
}

// TODO: might want to put a lock around the putMsg rpc, but not clear what would be inside the CS.
func (myClient *client) putMsg(text *string) error {
	msg := &pb.Msg{
		Sender: myClient.myData.name, Text: *text,
	}

	// Compute hash of prior msg.
	myClient.lastMsg.mu.Lock()
	defer myClient.lastMsg.mu.Unlock()
	priorHash, err := myClient.compHash(myClient.lastMsg.msg)
	if err != nil {
		return err
	}
	msgHash := &pb.MsgHash{
		Msg: msg, Hash: priorHash,
	}

	// Sign the current msg.
	currHash, err := myClient.compHash(msgHash)
	if err != nil {
		return err
	}
	sig, err := rsa.SignPSS(rand.Reader, myClient.myData.privKey, crypto.SHA512, currHash, nil)
	if err != nil {
		return err
	}
	msgHashSig := &pb.MsgHashSig{
		MsgHash: msgHash, Sig: sig,
	}

	// Send it out.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err = myClient.rpc.PutMsg(ctx, &pb.PutMsgReq{MsgHashSig: msgHashSig}); err != nil {
		return err
	}
	myClient.lastMsg.msg = msg
	return nil
}

func (myClient *client) runMsgLoop() {
	for {
		prompt := promptui.Select{
			Label: "Action",
			Items: []string{"PutMsg", "End"},
		}
		_, action, err := prompt.Run()
		if err != nil {
			log.Println("warning: failed prompt:", err)
			continue
		}

		if action == "End" {
			return
		} else if action == "PutMsg" {
			prompt := promptui.Prompt{
				Label: "Msg",
			}
			msg, err := prompt.Run()
			if err != nil {
				log.Println("warning: failed prompt:", err)
				continue
			}
			if err = myClient.putMsg(&msg); err != nil {
				log.Println("failed putMsg:", err)
			}
		} else {
			log.Println("warning: unrecognized action:", action)
		}
	}
}

func main() {
	myClient, conn := newClient()
	defer conn.Close()
	myClient.runNameLoop()
	if err := myClient.loadKeys(); err != nil {
		log.Fatalln("failed to load keys:", err)
	}
	go myClient.getMsgs()
	myClient.runMsgLoop()
}
