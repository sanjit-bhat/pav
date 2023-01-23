package main

import (
    "context"
    "flag"
    "fmt"
    "log"
    "net"
    "os"

    "google.golang.org/grpc"
    pb "example.com/rpc"
)

var (
    port = flag.Int("port", 50051, "Server port")
)

type server struct {
    pb.UnimplementedSharerServer
}

func (s *server) PutPhoto(ctx context.Context, in *pb.PhotoRequest) (*pb.PhotoReply, error) {
    log.Printf("Received new photo")    
    uploadDir := "server/uploads/"
    fileName := "example.jpg"
    filePath := uploadDir + fileName 
    file, err := os.Create(filePath)
    if err != nil {
        log.Fatalln("failed to create file: ", err)
    }
    defer file.Close()

    _, err = file.Write(in.GetFile())
    if err != nil {
        log.Fatalln("failed to write file: ", err)
    }

    return &pb.PhotoReply{Path: fileName}, nil 
}

func main() {
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
