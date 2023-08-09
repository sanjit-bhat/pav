package main

import (
	"context"
	"log"
	"net"
	"sync"
	"sync/atomic"

	pb "example.com/internal/protoDefs"
	"google.golang.org/grpc"
)

type server struct {
	pb.UnimplementedChatServer
	seqNum atomic.Uint64
	mu     sync.Mutex
	msgs   []*pb.MsgWrap
	newMsg sync.Cond
}

func newServer() *server {
	serv := &server{}
	serv.newMsg.L = &serv.mu
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalln("failed to listen to port:", err)
	}
	grpcServ := grpc.NewServer()
	pb.RegisterChatServer(grpcServ, serv)
	log.Println("server listening at:", lis.Addr())
	if err := grpcServ.Serve(lis); err != nil {
		log.Fatalln("failed to serve:", err)
	}
	return serv
}

// Send pending msgs. Assumes lock held. Releases lock.
func (serv *server) sendPending(msgsIdx *int, stream pb.Chat_GetMsgsServer) error {
	msgs := serv.msgs
	msgsLen := len(msgs)
	pending := make([]*pb.MsgWrap, msgsLen-*msgsIdx)
	copy(pending, msgs[*msgsIdx:msgsLen])
	serv.mu.Unlock()

	for _, msg := range pending {
		resp := pb.GetMsgsResp{Msg: msg}
		if err := stream.Send(&resp); err != nil {
			return err
		}
	}
	*msgsIdx = msgsLen
	return nil
}

func (serv *server) GetMsgs(in *pb.GetMsgsReq, stream pb.Chat_GetMsgsServer) error {
	msgsIdx := new(int)
	serv.mu.Lock()
	if err := serv.sendPending(msgsIdx, stream); err != nil {
		return err
	}

	for {
		serv.mu.Lock()
		for !(*msgsIdx < len(serv.msgs)) {
			serv.newMsg.Wait()
		}
		if err := serv.sendPending(msgsIdx, stream); err != nil {
			return err
		}
	}
}

func (serv *server) PutMsg(ctx context.Context, in *pb.PutMsgReq) (*pb.PutMsgResp, error) {
	msg := in.Msg
	msg.SeqNum = serv.seqNum.Add(1)

	serv.mu.Lock()
	serv.msgs = append(serv.msgs, msg)
	serv.newMsg.Broadcast()
	serv.mu.Unlock()

	return &pb.PutMsgResp{}, nil
}

func main() {
	newServer()
}
