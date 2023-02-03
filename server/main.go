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
	port = 50051
	uploadsDir = "server/uploads/"
)

type server struct {
	pb.UnimplementedSharerServer
}

//type serverInMem struct {

	// map of users to their photos	
	// register user
	// map of users to their   
//}

func (s *server) PutPhoto(ctx context.Context, in *pb.PutPhotoReq) (*pb.PutPhotoResp, error) {
	log.Printf("Received photo")
	fileName := fmt.Sprintf("file-%d.jpg", rand.Intn(1000))
	uploadsDirUser := uploadsDir + in.GetName() + "/"
	err := os.MkdirAll(uploadsDirUser, 0777)
	if err != nil {
		log.Fatalln("failed to create user uploads dir:", err)
	}
	filePath := uploadsDirUser + fileName
	err = os.WriteFile(filePath, in.GetData(), 0777)
	if err != nil {
		log.Fatalln("failed to create/write file:", err)
	}	
	return &pb.PutPhotoResp{File: fileName}, nil
}

func (s *server) GetPhoto(ctx context.Context, in *pb.GetPhotoReq) (*pb.GetPhotoResp, error) {
	log.Printf("Getting photo")
	filePath := uploadsDir + in.GetName() + "/" + in.GetFile()
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Println("failed to find file:", filePath)
		return nil, err
	}
	return &pb.GetPhotoResp{Data: data}, nil	
}

func (s *server) ListPhotos(ctx context.Context, in *pb.ListPhotosReq) (*pb.ListPhotosResp, error) {
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
	return &pb.ListPhotosResp{Files: imgs}, nil
}

func main() {
	rand.Seed(time.Now().UTC().UnixNano())
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalln("failed to listen to port:", err)
	}
	s := grpc.NewServer()
	pb.RegisterSharerServer(s, &server{})
	log.Println("server listening at ", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalln("failed to serve:", err)
	}
}
