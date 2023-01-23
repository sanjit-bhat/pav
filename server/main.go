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

	pb "example.com/rpc"
	"google.golang.org/grpc"
)

var (
	port = flag.Int("port", 50051, "Server port")
	uploadsDir = "server/uploads/"
)

type server struct {
	pb.UnimplementedSharerServer
}

func (s *server) AddPhoto(ctx context.Context, in *pb.AddPhotoReq) (*pb.AddPhotoResp, error) {
	log.Printf("Received new photo")
	fileName := fmt.Sprintf("file-%d.jpg", rand.Intn(1000))
	filePath := uploadsDir + fileName
	file, err := os.Create(filePath)
	if err != nil {
		log.Fatalln("failed to create file: ", err)
	}
	defer file.Close()

	_, err = file.Write(in.GetFile())
	if err != nil {
		log.Fatalln("failed to write file: ", err)
	}

	return &pb.AddPhotoResp{Path: fileName}, nil
}

func (s *server) ListPhotos(ctx context.Context, in *pb.ListPhotosReq) (*pb.ListPhotosResp, error) {
	log.Printf("Getting list of photos")
	file, err := os.Open(uploadsDir)
	if err != nil {
		log.Fatalln("failed to open uploads dir: ", err)
	}	
	defer file.Close()

	imgs, err := file.Readdirnames(0)
	if err != nil {
		log.Fatalln("failed to read uploads dir: ", err)
	}
	return &pb.ListPhotosResp{Paths: imgs}, nil
}

func main() {
	rand.Seed(time.Now().UTC().UnixNano())
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalln("failed to listen to port: ", err)
	}
	s := grpc.NewServer()
	pb.RegisterSharerServer(s, &server{})
	log.Println("server listening at ", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalln("failed to serve: ", err)
	}
}
