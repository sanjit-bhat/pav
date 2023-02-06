package main

import (
	"context"
	"log"
	"sort"
	"time"

	pb "example.com/chatGrpc"
	"github.com/manifoldco/promptui"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type userMetadata struct {
	name         string
	latestSeqNum uint64
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
	db.myUserData = new(userMetadata)
	db.allUserData = make(map[string]*userMetadata)
	return &db
}

func loginUserHandler(db *inMem, name *string) {
	db.myUserData.name = *name
}

func createUserHandler(client pb.ChatClient, db *inMem, name *string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := client.CreateUser(ctx, &pb.CreateUserReq{Name: *name})
	if err != nil {
		log.Println("failed to create user:", err)
	} else {
		db.myUserData.name = *name
	}
}

func listMsgsHandler(db *inMem) {
	log.Println("All messages:")
	for _, msg := range db.msgs {
		log.Printf("`%v` [%v]: \"%v\"\n", msg.sender, msg.time.Format(time.UnixDate), msg.msg)
	}
}

func putMsgHandler(client pb.ChatClient, db *inMem, msg *string) {
	newSeqNum := db.myUserData.latestSeqNum + 1
	currTime := time.Now()
	currTimeBytes, err := currTime.MarshalText()
	if err != nil {
		log.Println("failed to marshal time:", err)
		return
	}
	currTimeStr := string(currTimeBytes)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = client.PutMsg(ctx, &pb.PutMsgReq{MsgData: &pb.MsgData{
		Sender: db.myUserData.name, Msg: *msg, SeqNum: newSeqNum, Time: currTimeStr,
	}})
	if err != nil {
		log.Println("failed to put msg:", err)
		return
	}
	db.myUserData.latestSeqNum = newSeqNum
	db.msgs = append(db.msgs, &msgData{
		sender: db.myUserData.name, msg: *msg, seqNum: newSeqNum, time: currTime,
	})
}

func (db *inMem) isValidMsg(newMsg *msgData) bool {
	userData := db.allUserData[newMsg.sender]
	return userData.latestSeqNum+1 == newMsg.seqNum
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
	} else {
		for _, synchMsg := range synchResp.GetMsgs() {
			newTime := new(time.Time)
			err = newTime.UnmarshalText([]byte(synchMsg.GetTime()))
			if err != nil {
				log.Println("failed to unmarshal text:", err)
				continue
			}
			newMsg := msgData{
				sender: synchMsg.GetSender(),
				msg:    synchMsg.GetMsg(),
				seqNum: synchMsg.GetSeqNum(),
				time:   *newTime,
			}
			userData, ok := db.allUserData[newMsg.sender]
			if !ok {
				userData = &userMetadata{name: newMsg.sender, latestSeqNum: 0}
				db.allUserData[newMsg.sender] = userData
			}
			if db.isValidMsg(&newMsg) {
				db.addMsg(&newMsg)
			} else {
				log.Printf("expected new msg to have seq num %v, got seq num %v\n, discarding...", userData.latestSeqNum+1, newMsg.seqNum)
			}
		}
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
