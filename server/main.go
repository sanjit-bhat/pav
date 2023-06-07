package main

import (
	"context"
	"log"
	"net"
	"sync"

	pb "example.com/protoDefs"
	"google.golang.org/grpc"
)

type uname string

type server struct {
	pb.UnimplementedChatServer
	msgs      []*pb.MsgWrap
	mailboxes map[uname]chan *pb.MsgWrap
	seqNum    uint64
	seqNumMu  sync.Mutex
}

func newServer() *server {
	serv := &server{}
	serv.mailboxes = make(map[uname]chan *pb.MsgWrap)

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

func (serv *server) GetMsgs(in *pb.GetMsgsReq, stream pb.Chat_GetMsgsServer) error {
	// Send all the prior msgs.
	for _, msg := range serv.msgs {
		resp := pb.GetMsgsResp{Msg: msg}
		if err := stream.Send(&resp); err != nil {
			return err
		}
	}

	// Wait for new messages and send them to the client.
	mailbox := make(chan *pb.MsgWrap)
	serv.mailboxes[uname(in.Sender)] = mailbox

	for {
		newMsg, more := <-mailbox
		if !more {
			return nil
		}
		resp := pb.GetMsgsResp{Msg: newMsg}
		if err := stream.Send(&resp); err != nil {
			return err
		}
	}
}

func (serv *server) PutMsg(ctx context.Context, in *pb.PutMsgReq) (*pb.PutMsgResp, error) {
	msg := in.Msg
	sender := msg.Msg.Sender

	serv.seqNumMu.Lock()
	serv.seqNum += 1
	msg.SeqNum = serv.seqNum
	serv.msgs = append(serv.msgs, msg)
	serv.seqNumMu.Unlock()

	for recvr, ch := range serv.mailboxes {
		if string(recvr) != sender {
			ch <- msg
		}
	}
	return &pb.PutMsgResp{SeqNum: msg.SeqNum}, nil
}

func main() {
	newServer()
}
