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

type msgsProt struct {
	mu   sync.Mutex
	data []*pb.MsgWrap
}

type mailboxesProt struct {
	mu   sync.Mutex
	data map[uname]chan notifT
}

type uname string
type notifT struct{}
type server struct {
	pb.UnimplementedChatServer
	seqNum    atomic.Uint64
	msgs      msgsProt
	mailboxes mailboxesProt
}

func newServer() *server {
	serv := &server{}
	serv.mailboxes.data = make(map[uname]chan notifT)

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalln("failed to listen to port:", err)
	}
	grpcServ := grpc.NewServer()
	pb.RegisterChatServer(grpcServ, serv)
	log.Println("server listening at ", lis.Addr())
	if err := grpcServ.Serve(lis); err != nil {
		log.Fatalln("failed to serve:", err)
	}
	return serv
}

func (serv *server) sendPending(msgsIdx *int, stream pb.Chat_GetMsgsServer) error {
	serv.msgs.mu.Lock()
	msgs := serv.msgs.data
	msgsLen := len(msgs)
	pending := make([]*pb.MsgWrap, msgsLen-*msgsIdx)
	copy(pending, msgs[*msgsIdx:msgsLen])
	serv.msgs.mu.Unlock()

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
	mailbox := make(chan notifT, 10)
	serv.mailboxes.mu.Lock()
	serv.mailboxes.data[uname(in.Sender)] = mailbox
	serv.mailboxes.mu.Unlock()

	msgsIdx := new(int)
	if err := serv.sendPending(msgsIdx, stream); err != nil {
		return err
	}

	for {
		_, more := <-mailbox
		if !more {
			return nil
		}
		if err := serv.sendPending(msgsIdx, stream); err != nil {
			return err
		}
	}
}

func (serv *server) PutMsg(ctx context.Context, in *pb.PutMsgReq) (*pb.PutMsgResp, error) {
	msg := in.Msg

	msg.SeqNum = serv.seqNum.Add(1)

	serv.msgs.mu.Lock()
	serv.msgs.data = append(serv.msgs.data, msg)
	serv.msgs.mu.Unlock()

	// This CS should not deadlock.
	// The channel read is not acquiring the mailbox lock.
	// It is acquiring the msgs lock, but that should always make progress.
	serv.mailboxes.mu.Lock()
	for _, ch := range serv.mailboxes.data {
		ch <- notifT{}
	}
	serv.mailboxes.mu.Unlock()

	return &pb.PutMsgResp{}, nil
}

func main() {
	newServer()
}
