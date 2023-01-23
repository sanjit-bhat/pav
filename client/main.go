package main

import (
	"context"
	"flag"
	"log"
	"os"
	"time"

	pb "example.com/rpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	addr = flag.String("addr", "localhost:50051", "server address")
	file = flag.String("file", "frans.jpg", "path to photo file: used for adding photos")
	modeAdd = flag.Bool("add", false, "mode: add photo to server")
	modeList = flag.Bool("list", false, "mode: list photos in server")
	name = flag.String("name", "sanjit", "client name")
)

func main() {
	flag.Parse()
	conn, err := grpc.Dial(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalln("failed to connect: ", err)
	}
	defer conn.Close()
	c := pb.NewSharerClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if *modeAdd {
		fullFile := "client/photos/" + *file
		data, err := os.ReadFile(fullFile)
		if err != nil {
			log.Fatalln("failed to read file: ", err)
		}
		resp, err := c.PutPhoto(ctx, &pb.PutPhotoReq{Data: data})
		if err != nil {
			log.Fatalln("could not put photo: ", err)
		}
		log.Println("File is saved under: ", resp.GetFile())
	} else if *modeList {
		resp, err := c.ListPhotos(ctx, &pb.ListPhotosReq{Name: *name})	
		if err != nil {
			log.Fatalln("failed to list photos: ", err)
		}
		log.Println("Available photos: ", resp.GetFiles())
	}
}
