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
	"time"

	pb "example.com/chatGrpc"
	"github.com/manifoldco/promptui"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

type userMetadata struct {
	pubKey       *rsa.PublicKey
}

type myMetadata struct {
	userMetadata 
	name string
	privKey *rsa.PrivateKey
}

type msgData struct {
	sender string
	text   string
	time   time.Time
	hashChain []byte
}

type client struct {
	rpc pb.ChatClient
	myData *myMetadata
	// Key is the username.
	allData map[string]*userMetadata
	msgs []*msgData
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

func (myClient *client) loadKeys() error {
	fileBytes, err := os.ReadFile("demo_keys")
	if err != nil {
		return err
	}
	manyUserKeys := &pb.ManyUserKeys{}
	if err := proto.Unmarshal(fileBytes, manyUserKeys); err != nil {
		return err
	}

	for _, userKey := range manyUserKeys.GetUserKeys() {
		pubKey, err := x509.ParsePKCS1PublicKey(userKey.GetPubKey())
		if err != nil {
			return err
		}

		if myClient.myData.name == userKey.GetName() {
			privKey, err := x509.ParsePKCS1PrivateKey(userKey.GetPrivKey())
			if err != nil {
				return err
			}
			myClient.myData.privKey = privKey
			myClient.myData.pubKey = pubKey
		} else {
			user, ok := myClient.allData[userKey.GetName()]
			if !ok {
				user = &userMetadata{}
				myClient.allData[userKey.GetName()] = user
			}
			user.pubKey = pubKey
		}
	}
	return nil
}

func (myClient *client) compHashChain(msg *pb.Msg) ([]byte, error) {
	bytesForChain, err := proto.Marshal(msg)
	if err != nil {
		return nil, err
	}
	if len(myClient.msgs) > 0 {
		bytesForChain = append(myClient.msgs[len(myClient.msgs) - 1].hashChain, bytesForChain...)
	}
	hashForChain := sha512.Sum512(bytesForChain)
	return hashForChain[:], nil
}

func (myClient *client) isValidMsg(msgHashSig *pb.MsgHashSig) error {
	// Check signature.
	msgHash := msgHashSig.GetMsgHash()
	msg := msgHash.GetMsg()
	sender := msg.GetSender() 
	userData, ok := myClient.allData[sender]
	if !ok {
		return errors.New("don't have public key for user")
	}

	bytesForSig, err := proto.Marshal(msgHash)
	if err != nil {
		return err
	}
	preHashForSig := sha512.Sum512(bytesForSig)
	hashForSig := preHashForSig[:]
	if err := rsa.VerifyPSS(userData.pubKey, crypto.SHA512, hashForSig, msgHashSig.GetSig(), nil); err != nil {
		return err
	}

	// Check hash chain.
	hashForChain, err := myClient.compHashChain(msg)
	if err != nil {
		return err
	}
	if !bytes.Equal(hashForChain, msgHash.GetHashChain()) {
		return errors.New("failed to verify hash chain")
	}

	return nil
}

func (myClient *client) tryAddNewMsg(getMsgsResp *pb.GetMsgsResp) error {
	msgHashSig := getMsgsResp.GetMsgHashSig()
	msgHash := msgHashSig.GetMsgHash()
	msg := msgHash.GetMsg()

	if err := myClient.isValidMsg(msgHashSig); err != nil {
		return err
	}
	newTime := new(time.Time)
	if err := newTime.UnmarshalBinary(msg.GetTime()); err != nil {
		return err
	}
	newMsg := msgData{
		sender: msg.GetSender(),
		text:   msg.GetText(),
		time:   *newTime,
		hashChain: msgHash.GetHashChain(),
	}
	myClient.msgs = append(myClient.msgs, &newMsg)
	log.Printf("`%v` [%v]: \"%v\"\n", newMsg.sender, newMsg.time.Format(time.UnixDate), newMsg.text)
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
        msg, err := stream.Recv()
        if err == io.EOF {
            return
        }
        if err != nil {
            log.Fatalln("failed getMsgs stream recv:", err)
        }
		if err = myClient.tryAddNewMsg(msg); err != nil {
			log.Println("failed to add msg:", err)
		}
    }
}

func (myClient *client) putMsg(text *string) error {
	currTime := time.Now()
	currTimeBytes, err := currTime.MarshalBinary()
	if err != nil {
		return err
	}
	msg := &pb.Msg{
		Sender: myClient.myData.name, Text: *text, Time: currTimeBytes,
	}

	// Compute hash chain.
	hashChain, err := myClient.compHashChain(msg)
	if err != nil {
		return err
	}
	msgHash := &pb.MsgHash{
		Msg: msg, HashChain: hashChain,
	}

	// Sign the msg. 
	bytesForSigHash, err := proto.Marshal(msgHash)
	if err != nil {
		return err
	}
	preHashForSig := sha512.Sum512(bytesForSigHash)
	hashForSig := preHashForSig[:]
	sig, err := rsa.SignPSS(rand.Reader, myClient.myData.privKey, crypto.SHA512, hashForSig, nil)
	if err != nil {
		return err
	}	
	msgHashSig := &pb.MsgHashSig{
		MsgHash: msgHash, Sig: sig,
	}

	// Send it out.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = myClient.rpc.PutMsg(ctx, &pb.PutMsgReq{MsgHashSig: msgHashSig})
	if err != nil {
		return err
	}
	myClient.msgs = append(myClient.msgs, &msgData{
		sender: msg.GetSender(), text: msg.GetText(), time: currTime,
	})
	return nil
}

func (myClient *client) runNameLoop() {
	for {
		prompt := promptui.Prompt{
			Label: "Name",
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
			err = myClient.putMsg(&msg)
			if err != nil {
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
	err := myClient.loadKeys()
	if err != nil {
		log.Fatalln("failed to load keys:", err)
	}
	go myClient.getMsgs()
	myClient.runMsgLoop()	
}
