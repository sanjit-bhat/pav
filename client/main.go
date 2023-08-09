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
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"example.com/internal/promptui"
	pb "example.com/internal/protoDefs"
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
	rpc     pb.ChatClient
	myData  *myMetadata
	allData map[unameT]*userMetadata
	msgs    msgsProt
	cancel  cancelProt
}

func newClient() (*client, *grpc.ClientConn) {
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalln("failed to connect:", err)
	}
	c := &client{rpc: pb.NewChatClient(conn)}
	c.myData = &myMetadata{}
	c.allData = make(map[unameT]*userMetadata)
	c.msgs.data = make(map[seqNumT]*pb.MsgWrap)
	return c, conn
}

func (myClient *client) runNameLoop() {
	for {
		prompt := promptui.Select{
			Label: "Name",
			Items: []string{"alice", "bob", "charlie", "danny", "eve"},
		}
		name, err := prompt.Run()
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

		// Want this client's public key credentials to appear both in
		// allData and myData so that this client can `get` its own msgs.
		user, ok := myClient.allData[unameT(userKey.Name)]
		if !ok {
			user = &userMetadata{}
			myClient.allData[unameT(userKey.Name)] = user
		}
		user.pubKey = pubKey

		if myClient.myData.name == userKey.Name {
			privKey, err := x509.ParsePKCS1PrivateKey(userKey.PrivKey)
			if err != nil {
				return err
			}
			myClient.myData.privKey = privKey
			myClient.myData.pubKey = pubKey
		}
	}

	if myClient.myData.privKey == nil {
		return errors.New("do not have private key for user")
	}
	return nil
}

func hash(msg proto.Message) ([]byte, error) {
	bytes, err := proto.Marshal(msg)
	if err != nil {
		return nil, err
	}
	hash := sha512.Sum512(bytes)
	return hash[:], nil
}

func checkHash(msgWrap *pb.MsgWrap) error {
	refHash, err := hash(msgWrap.Msg)
	if err != nil {
		return err
	}
	if !bytes.Equal(refHash, msgWrap.Hash) {
		return errors.New("given hash does not match reference hash")
	}
	return nil
}

func (myClient *client) checkSig(msgWrap *pb.MsgWrap) error {
	userData, ok := myClient.allData[unameT(msgWrap.Msg.Sender)]
	if !ok {
		return errors.New("do not have public key for user")
	}
	if err := rsa.VerifyPSS(userData.pubKey, crypto.SHA512, msgWrap.Hash, msgWrap.Sig, nil); err != nil {
		return err
	}
	return nil
}

func (myClient *client) checkPins(msgWrap *pb.MsgWrap) error {
	myClient.msgs.mu.Lock()
	defer myClient.msgs.mu.Unlock()
	msgs := myClient.msgs.data
	for _, pin := range msgWrap.Msg.Pins {
		pinnedMsg, ok := msgs[seqNumT(pin.SeqNum)]
		if !ok {
			return errors.New("pinned msg not contained in local history")
		}
		if msgWrap.SeqNum <= pinnedMsg.SeqNum {
			return errors.New("pinned msg has greater seqNum than actual msg")
		}
		if !bytes.Equal(pinnedMsg.Hash, pin.Hash) {
			return errors.New("pin has diff msg hash than local history")
		}
	}
	return nil
}

func (myClient *client) checkDupSeqNumAndAdd(msgWrap *pb.MsgWrap) error {
	myClient.msgs.mu.Lock()
	defer myClient.msgs.mu.Unlock()
	msgs := myClient.msgs.data
	if _, ok := msgs[seqNumT(msgWrap.SeqNum)]; ok {
		return errors.New("seqNum already exists in local history")
	}
	msgs[seqNumT(msgWrap.SeqNum)] = msgWrap
	return nil
}

func (myClient *client) checkAndAddRcvdMsg(msgWrap *pb.MsgWrap) error {
	if err := checkHash(msgWrap); err != nil {
		return err
	}
	// Note: sig check relies on hash check occuring *before* it.
	if err := myClient.checkSig(msgWrap); err != nil {
		return err
	}
	if err := myClient.checkPins(msgWrap); err != nil {
		return err
	}
	if err := myClient.checkDupSeqNumAndAdd(msgWrap); err != nil {
		return err
	}
	return nil
}

var errUserEndClient = errors.New("user ended the client")

func (myClient *client) setCancel(f context.CancelCauseFunc) error {
	myClient.cancel.mu.Lock()
	defer myClient.cancel.mu.Unlock()
	if myClient.cancel.done {
		return errors.New("client already ended connection")
	} else {
		myClient.cancel.data = f
		return nil
	}
}

func (myClient *client) getMsgs() {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	if err := myClient.setCancel(cancel); err != nil {
		return
	}
	stream, err := myClient.rpc.GetMsgs(ctx, &pb.GetMsgsReq{Sender: myClient.myData.name})
	if err != nil {
		log.Fatalln("failed getMsgs:", err)
	}

	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			log.Println("server closed getMsgs stream")
			return
		}
		if err != nil {
			if errors.Is(context.Cause(ctx), errUserEndClient) {
				return
			} else {
				log.Fatalln("failed getMsgs stream recv:", err)
			}
		}
		if err = myClient.checkAndAddRcvdMsg(resp.Msg); err != nil {
			log.Println("failed to add msg:", err)
		}
	}
}

func (myClient *client) getPins() []*pb.Pin {
	myClient.msgs.mu.Lock()
	defer myClient.msgs.mu.Unlock()
	msgs := myClient.msgs.data
	pins := make([]*pb.Pin, 0, len(msgs))
	for seqNum, msgWrap := range msgs {
		pin := &pb.Pin{
			SeqNum: uint64(seqNum), Hash: msgWrap.Hash,
		}
		pins = append(pins, pin)
	}
	return pins
}

func (myClient *client) hashAndSignMsg(msg *pb.Msg) (*pb.MsgWrap, error) {
	msgWrap := &pb.MsgWrap{}
	msgWrap.Msg = msg
	hash, err := hash(msg)
	if err != nil {
		return nil, err
	}
	msgWrap.Hash = hash
	sig, err := rsa.SignPSS(rand.Reader, myClient.myData.privKey, crypto.SHA512, hash, nil)
	if err != nil {
		return nil, err
	}
	msgWrap.Sig = sig
	return msgWrap, nil
}

func (myClient *client) putMsg(body *string) error {
	pins := myClient.getPins()
	msg := &pb.Msg{
		Sender: myClient.myData.name, Body: *body, Pins: pins,
	}
	msgWrap, err := myClient.hashAndSignMsg(msg)
	if err != nil {
		return err
	}

	for {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := myClient.rpc.PutMsg(ctx, &pb.PutMsgReq{Msg: msgWrap})
		// Need to cancel now, as opposed to deferring, to not leak contexts inside loop.
		cancel()
		if err != nil {
			log.Println("put rpc returned an err, retrying...")
		} else {
			break
		}
	}
	return nil
}

func (myClient *client) listMsgs() {
	myClient.msgs.mu.Lock()
	defer myClient.msgs.mu.Unlock()
	msgs := myClient.msgs.data
	for seqNum, msg := range msgs {
		fmt.Printf("[%v] [%v]: \"%v\"\n", seqNum, msg.Msg.Sender, msg.Msg.Body)
	}
}

func (myClient *client) callCancel() {
	myClient.cancel.mu.Lock()
	defer myClient.cancel.mu.Unlock()
	if myClient.cancel.data != nil {
		myClient.cancel.data(errUserEndClient)
	} else {
		myClient.cancel.done = true
	}
}

func (myClient *client) runMsgLoop() {
	for {
		prompt := promptui.Select{
			Label: "Action",
			Items: []string{"put", "list", "end"},
		}
		action, err := prompt.Run()
		if err != nil {
			log.Println("warning: failed prompt:", err)
			continue
		}

		if action == "end" {
			myClient.callCancel()
			return
		} else if action == "list" {
			myClient.listMsgs()
		} else if action == "put" {
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
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		myClient.getMsgs()
	}()
	go func() {
		defer wg.Done()
		myClient.runMsgLoop()
	}()
	wg.Wait()
}
