package main

import (
	"context"
	"log"
	"net"

	pb "example.com/chatGrpc"
	"google.golang.org/grpc"
)

type server struct {
	pb.UnimplementedChatServer
	msgs      []*pb.MsgHashSig
	mailboxes map[string]chan *pb.MsgHashSig
}

func newServer() *server {
	serv := &server{}
	serv.mailboxes = make(map[string]chan *pb.MsgHashSig)

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
		resp := pb.GetMsgsResp{MsgHashSig: msg}
		if err := stream.Send(&resp); err != nil {
			return err
		}
	}

	// Wait for new messages and send them to the client.
	mailbox := make(chan *pb.MsgHashSig)
	serv.mailboxes[in.GetSender()] = mailbox

	for {
		newMsg, more := <-mailbox
		if !more {
			return nil
		}
		resp := pb.GetMsgsResp{MsgHashSig: newMsg}
		if err := stream.Send(&resp); err != nil {
			return err
		}
	}
}

func (serv *server) PutMsg(ctx context.Context, in *pb.PutMsgReq) (*pb.PutMsgResp, error) {
	msg := in.GetMsgHashSig()
	sender := msg.GetMsgHash().GetMsg().GetSender()
	serv.msgs = append(serv.msgs, msg)
	for recvr, ch := range serv.mailboxes {
		if recvr != sender {
			ch <- msg
		}
	}
	return &pb.PutMsgResp{}, nil
}

func main() {
	newServer()
}
