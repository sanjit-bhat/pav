package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"log"
	"os"
	"sort"
	"time"

	pb "example.com/chatGrpc"
	"github.com/manifoldco/promptui"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

type userMetadata struct {
	name         string
	latestSeqNum uint64
	privKey      *rsa.PrivateKey
	pubKey       *rsa.PublicKey
}

type msgData struct {
	sender string
	msg    string
	seqNum uint64
	time   time.Time
}

type inMem struct {
	myUserData  *userMetadata
	allUserData map[string]*userMetadata
	// Invariant: `msgs` always sorted by earliest time first
	msgs []*msgData
}

func newInMem() *inMem {
	db := inMem{}
	db.myUserData = &userMetadata{}
	db.allUserData = make(map[string]*userMetadata)
	return &db
}

func loginUserHandler(db *inMem, name *string) {
	db.myUserData.name = *name

	fileBytes, err := os.ReadFile("demo_keys")
	if err != nil {
		log.Println("failed to read key file:", err)
		return
	}
	manyUserKeys := &pb.ManyUserKeys{}
	if err := proto.Unmarshal(fileBytes, manyUserKeys); err != nil {
		log.Println("failed to unmarshal keys:", err)
		return
	}

	for _, userKey := range manyUserKeys.GetUserKeys() {
		pubKey, err := x509.ParsePKCS1PublicKey(userKey.GetPubKey())
		if err != nil {
			log.Println("failed to parse pub key:", err)
			return
		}

		if *name == userKey.GetName() {
			privKey, err := x509.ParsePKCS1PrivateKey(userKey.GetPrivKey())
			if err != nil {
				log.Println("failed to parse priv key:", err)
				return
			}
			db.myUserData.privKey = privKey
			db.myUserData.pubKey = pubKey
		} else {
			user, ok := db.allUserData[userKey.GetName()]
			if !ok {
				user = &userMetadata{}
				db.allUserData[userKey.GetName()] = user
			}
			user.pubKey = pubKey
		}
	}
}

func createUserHandler(client pb.ChatClient, db *inMem, name *string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := client.CreateUser(ctx, &pb.CreateUserReq{Name: *name})
	if err != nil {
		log.Println("failed to create user:", err)
		return
	}
	loginUserHandler(db, name)
}

func listMsgsHandler(db *inMem) {
	log.Println("All messages:")
	for _, msg := range db.msgs {
		log.Printf("`%v` [%v]: \"%v\"\n", msg.sender, msg.time.Format(time.UnixDate), msg.msg)
	}
}

func hashMsgData(msg *pb.MsgData) ([]byte, error) {
	bytes, err := proto.Marshal(msg)
	if err != nil {
		return nil, errors.New("failed to marshal msgData")
	}
	hash := sha512.Sum512(bytes)
	return hash[:], nil
}

func signMsgData(db *inMem, msg *pb.MsgData) ([]byte, error) {
	hash, err := hashMsgData(msg)
	if err != nil {
		return nil, err
	}
	return rsa.SignPSS(rand.Reader, db.myUserData.privKey, crypto.SHA512, hash[:], nil)
}

func putMsgHandler(client pb.ChatClient, db *inMem, msg *string) {
	newSeqNum := db.myUserData.latestSeqNum + 1
	currTime := time.Now()
	currTimeBytes, err := currTime.MarshalBinary()
	if err != nil {
		log.Println("failed to marshal time:", err)
		return
	}

	pbMsgData := &pb.MsgData{
		Sender: db.myUserData.name, Msg: *msg, SeqNum: newSeqNum, Time: currTimeBytes,
	}
	sig, err := signMsgData(db, pbMsgData)
	if err != nil {
		log.Println("failed to sign msg:", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = client.PutMsg(ctx, &pb.PutMsgReq{Msg: &pb.MsgDataSig{Msg: pbMsgData, Sig: sig}})
	if err != nil {
		log.Println("failed to put msg:", err)
		return
	}
	db.myUserData.latestSeqNum = newSeqNum
	db.msgs = append(db.msgs, &msgData{
		sender: db.myUserData.name, msg: *msg, seqNum: newSeqNum, time: currTime,
	})
}

func (db *inMem) isValidMsg(msg *pb.MsgDataSig) error {
	sender := msg.GetMsg().GetSender()
	seqNum := msg.GetMsg().GetSeqNum()
	userData, ok := db.allUserData[sender]
	if !ok {
		return errors.New("don't have public key for user")
	}
	if userData.latestSeqNum+1 != seqNum {
		return errors.New("unexpected seq num")
	}

	hash, err := hashMsgData(msg.GetMsg())
	if err != nil {
		return err
	}
	if err := rsa.VerifyPSS(userData.pubKey, crypto.SHA512, hash, msg.GetSig(), nil); err != nil {
		return err
	}
	return nil
}

func (db *inMem) addMsg(newMsg *msgData) {
	userData := db.allUserData[newMsg.sender]
	userData.latestSeqNum += 1
	// Lambda returns false for some prefix of list, then true for remainder
	insertIdx := sort.Search(len(db.msgs), func(i int) bool { return newMsg.time.Before(db.msgs[i].time) })
	insertAtEnd := insertIdx == len(db.msgs)
	db.msgs = append(db.msgs, newMsg)
	if !insertAtEnd {
		copy(db.msgs[insertIdx+1:], db.msgs[insertIdx:])
		db.msgs[insertIdx] = newMsg
	}
}

func synchronizeHandler(client pb.ChatClient, db *inMem) {
	seqNums := make(map[string]*pb.UserSeqNum, len(db.allUserData))
	for name, userData := range db.allUserData {
		seqNums[name] = new(pb.UserSeqNum)
		seqNums[name].Name = userData.name
		seqNums[name].SeqNum = userData.latestSeqNum
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	synchResp, err := client.Synchronize(ctx, &pb.SynchronizeReq{Name: db.myUserData.name, SeqNums: seqNums})
	if err != nil {
		log.Println("failed to synchronize:", err)
		return
	}
	for _, synchMsg := range synchResp.GetMsgs() {
		if err := db.isValidMsg(synchMsg); err != nil {
			log.Println("failed to validate new msg:", err)
			return
		}

		newTime := new(time.Time)
		msg := synchMsg.GetMsg()
		if err := newTime.UnmarshalBinary(msg.GetTime()); err != nil {
			log.Println("failed to unmarshal time:", err)
			continue
		}
		newMsg := msgData{
			sender: msg.GetSender(),
			msg:    msg.GetMsg(),
			seqNum: msg.GetSeqNum(),
			time:   *newTime,
		}
		if _, ok := db.allUserData[newMsg.sender]; !ok {
			db.allUserData[newMsg.sender] = &userMetadata{name: newMsg.sender, latestSeqNum: 0}
		}
		db.addMsg(&newMsg)
	}
}

func main() {
	myDB := newInMem()
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalln("failed to connect:", err)
	}
	defer conn.Close()
	client := pb.NewChatClient(conn)

	for {
		prompt := promptui.Select{
			Label: "Op",
			Items: []string{"CreateUser", "LoginUser", "Synchronize", "PutMsg", "ListMsgs", "End"},
		}
		_, op, err := prompt.Run()
		if err != nil {
			log.Println("failed prompt:", err)
			continue
		}

		if op == "End" {
			return
		} else if op == "CreateUser" || op == "LoginUser" {
			prompt := promptui.Prompt{
				Label: "Username",
			}
			name, err := prompt.Run()
			if err != nil {
				log.Println("failed prompt:", err)
				continue
			}
			if op == "CreateUser" {
				createUserHandler(client, myDB, &name)
			} else {
				loginUserHandler(myDB, &name)
			}
		} else if op == "ListMsgs" {
			listMsgsHandler(myDB)
		} else if op == "PutMsg" {
			prompt := promptui.Prompt{
				Label: "Msg",
			}
			msg, err := prompt.Run()
			if err != nil {
				log.Println("failed prompt:", err)
				continue
			}
			putMsgHandler(client, myDB, &msg)
		} else if op == "Synchronize" {
			synchronizeHandler(client, myDB)
		}
	}
}
