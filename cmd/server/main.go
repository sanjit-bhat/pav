package main

import (
	"context"
	"log"
	"net"
	"sync"
	"sync/atomic"

	pb "github.com/mit-pdos/secure-chat/internal/proto"
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
func (s *server) sendPending(msgsIdx *int, stream pb.Chat_GetMsgsServer) error {
	msgs := s.msgs
	msgsLen := len(msgs)
	pending := make([]*pb.MsgWrap, msgsLen-*msgsIdx)
	copy(pending, msgs[*msgsIdx:msgsLen])
	s.mu.Unlock()

	for _, msg := range pending {
		resp := pb.GetMsgsResp{Msg: msg}
		if err := stream.Send(&resp); err != nil {
			return err
		}
	}
	*msgsIdx = msgsLen
	return nil
}

func (s *server) GetMsgs(in *pb.GetMsgsReq, stream pb.Chat_GetMsgsServer) error {
	msgsIdx := new(int)
	s.mu.Lock()
	if err := s.sendPending(msgsIdx, stream); err != nil {
		return err
	}

	for {
		s.mu.Lock()
		for !(*msgsIdx < len(s.msgs)) {
			s.newMsg.Wait()
		}
		if err := s.sendPending(msgsIdx, stream); err != nil {
			return err
		}
	}
}

func (s *server) PutMsg(ctx context.Context, in *pb.PutMsgReq) (*pb.PutMsgResp, error) {
	msg := in.Msg
	msg.SeqNum = s.seqNum.Add(1)

	s.mu.Lock()
	s.msgs = append(s.msgs, msg)
	s.newMsg.Broadcast()
	s.mu.Unlock()

	return &pb.PutMsgResp{}, nil
}

func main() {
	newServer()
}
