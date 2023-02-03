package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"time"

	pb "example.com/chatGrpc"
	"google.golang.org/grpc"
)

var (
	port = 50051
	uploadsDir = "server/uploads/"
)

type server struct {
	pb.UnimplementedChatServer
}

//type serverInMem struct {

	// map of users to their photos	
	// register user
	// map of users to their   
//}

func (s *server) PutMsg(ctx context.Context, in *pb.PutMsgReq) (*pb.PutMsgResp, error) {
	log.Printf("Received photo")
	return &pb.PutMsgResp{}, nil
}

func (s *server) GetMsgs(ctx context.Context, in *pb.GetMsgsReq) (*pb.GetMsgsResp, error) {
	log.Printf("Getting list of photos")
	uploadsDirUser := uploadsDir + in.GetName()
	file, err := os.Open(uploadsDirUser)
	if err != nil {
		log.Fatalln("failed to open uploads dir:", err)
	}	
	defer file.Close()

	imgs, err := file.Readdirnames(0)
	if err != nil {
		log.Fatalln("failed to read uploads dir:", err)
	}
	return &pb.GetMsgsResp{Msgs: imgs}, nil
}

func main() {
	rand.Seed(time.Now().UTC().UnixNano())
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalln("failed to listen to port:", err)
	}
	s := grpc.NewServer()
	pb.RegisterChatServer(s, &server{})
	log.Println("server listening at ", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalln("failed to serve:", err)
	}
}
