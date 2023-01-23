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
	modePut = flag.Bool("put", false, "mode: put photo onto server")
	modeGet = flag.Bool("get", false, "mode: get photo from server")
	modeList = flag.Bool("list", false, "mode: list photos on server")
	name = flag.String("name", "sanjit", "client name")
	photosDir = "client/photos/"
	getDir = "client/get/"
)

func putHandler(client pb.SharerClient, ctx context.Context) {
	log.Println("Putting a photo onto the server")
	filePath := photosDir + *file
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalln("failed to read file:", err)
	}
	resp, err := client.PutPhoto(ctx, &pb.PutPhotoReq{Name: *name, Data: data})
	if err != nil {
		log.Fatalln("could not put photo:", err)
	}
	log.Println("File is saved under:", resp.GetFile())
}

func getHandler(client pb.SharerClient, ctx context.Context) {
	log.Println("Getting a photo from the server")
	resp, err := client.GetPhoto(ctx, &pb.GetPhotoReq{Name: *name, File: *file})	
	if err != nil {
		log.Fatalln("could not get photo:", err)
	}
	err = os.MkdirAll(getDir, 0777)
	if err != nil {
		log.Fatalln("could not create get dir:", err)
	}	
	filePath := getDir + *file
	err = os.WriteFile(filePath, resp.GetData(), 0777)
	if err != nil {
		log.Fatalln("could not write file:", err)
	}
}

func listHandler(client pb.SharerClient, ctx context.Context) {
	log.Println("Getting a list of photos on the server")
	resp, err := client.ListPhotos(ctx, &pb.ListPhotosReq{Name: *name})	
	if err != nil {
		log.Fatalln("failed to list photos:", err)
	}
	log.Println("Available photos:", resp.GetFiles())
}

func main() {
	flag.Parse()
	conn, err := grpc.Dial(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalln("failed to connect:", err)
	}
	defer conn.Close()
	client := pb.NewSharerClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if *modePut {
		putHandler(client, ctx)
	} else if *modeGet {
		getHandler(client, ctx)
	} else if *modeList {
		listHandler(client, ctx)
	}
}
