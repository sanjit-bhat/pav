package main

import (
	"context"
	"errors"
	"log"
	"net"
	"sort"

	pb "example.com/chatGrpc"
	"google.golang.org/grpc"
)

type inMem struct {
	// key is username
	// invariant: msgs sorted by lowest seq num first
	userMsgs map[string][]*pb.MsgData
}

func newInMem() *inMem {
	db := inMem{}
	db.userMsgs = make(map[string][]*pb.MsgData)
	return &db
}

type server struct {
	pb.UnimplementedChatServer
	db *inMem
}

func (serv *server) CreateUser(ctx context.Context, in *pb.CreateUserReq) (*pb.CreateUserResp, error) {
	if _, ok := serv.db.userMsgs[in.GetName()]; ok {
		return nil, errors.New("username already exists")
	}
	serv.db.userMsgs[in.GetName()] = make([]*pb.MsgData, 0, 10)
	log.Println("created user")
	return &pb.CreateUserResp{}, nil
}

func (serv *server) PutMsg(ctx context.Context, in *pb.PutMsgReq) (*pb.PutMsgResp, error) {
	newMsgData := in.GetMsgData()
	msgs, ok := serv.db.userMsgs[newMsgData.GetSender()]
	if !ok {
		return nil, errors.New("username hasn't been created")
	}
	lastSeqNum := uint64(0)
	if len(msgs) > 0 {
		lastSeqNum = msgs[len(msgs)-1].GetSeqNum()
	}
	if lastSeqNum+1 != newMsgData.GetSeqNum() {
		return nil, errors.New("new msg seq num is out-of-order")
	}
	msgs = append(msgs, newMsgData)
	serv.db.userMsgs[newMsgData.GetSender()] = msgs
	log.Println("put new msg")
	return &pb.PutMsgResp{}, nil
}

func (serv *server) Synchronize(ctx context.Context, in *pb.SynchronizeReq) (*pb.SynchronizeResp, error) {
	unseenMsgs := []*pb.MsgData{}
	for name, msgs := range serv.db.userMsgs {
		if name == in.GetName() {
			// For now, assume that a user already has their own updates. This might change with multi-device
			continue
		}
		userSeqNum, ok := in.GetSeqNums()[name]
		lastSeenSeqNum := uint64(0)
		if ok {
			lastSeenSeqNum = userSeqNum.GetSeqNum()
		}
		// Inside lambda, LT, not LEQ, so get index after what client has already seen
		searchIdx := sort.Search(len(msgs), func(i int) bool { return lastSeenSeqNum < msgs[i].GetSeqNum() })
		unseenMsgs = append(unseenMsgs, msgs[searchIdx:]...)
	}
	log.Println("synchronized user")
	return &pb.SynchronizeResp{Msgs: unseenMsgs}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalln("failed to listen to port:", err)
	}
	grpcServ := grpc.NewServer()
	pb.RegisterChatServer(grpcServ, &server{db: newInMem()})
	log.Println("server listening at ", lis.Addr())
	if err := grpcServ.Serve(lis); err != nil {
		log.Fatalln("failed to serve:", err)
	}
}
