package main

import (
	"context"
	"log"
	"os"
	"time"

	pb "example.com/rpc"
	"github.com/manifoldco/promptui"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func putHandler(client pb.SharerClient, ctx context.Context, name string, file string, photosDir string) {
	log.Println("Putting a photo onto the server")
	filePath := photosDir + file
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalln("failed to read file:", err)
	}
	resp, err := client.PutPhoto(ctx, &pb.PutPhotoReq{Name: name, Data: data})
	if err != nil {
		log.Fatalln("could not put photo:", err)
	}
	log.Println("File is saved under:", resp.GetFile())
}

func getHandler(client pb.SharerClient, ctx context.Context, name string, file string, getDir string) {
	log.Println("Getting a photo from the server")
	resp, err := client.GetPhoto(ctx, &pb.GetPhotoReq{Name: name, File: file})
	if err != nil {
		log.Fatalln("could not get photo:", err)
	}
	err = os.MkdirAll(getDir, 0777)
	if err != nil {
		log.Fatalln("could not create get dir:", err)
	}
	filePath := getDir + file
	err = os.WriteFile(filePath, resp.GetData(), 0777)
	if err != nil {
		log.Fatalln("could not write file:", err)
	}
}

func listHandler(client pb.SharerClient, ctx context.Context, name string) {
	log.Println("Getting a list of photos on the server")
	resp, err := client.ListPhotos(ctx, &pb.ListPhotosReq{Name: name})
	if err != nil {
		log.Fatalln("failed to list photos:", err)
	}
	log.Println("Available photos:", resp.GetFiles())
}

func main() {
	addr := "localhost:50051"
	name := "sanjit"
	photosDir := "client/photos/"
	getDir := "client/get/"
	file := "frans.jpg"

	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalln("failed to connect:", err)
	}
	defer conn.Close()
	client := pb.NewSharerClient(conn)

	for {
		prompt := promptui.Select{
			Label: "Op",
			Items: []string{"Put", "Get", "List", "End"},
		}
		_, result, err := prompt.Run()
		if err != nil {
			log.Println("Prompt failed", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		switch result {
		case "End":
			return
		case "Put":
			putHandler(client, ctx, name, file, photosDir)
		case "Get":
			getHandler(client, ctx, name, file, getDir)
		case "List":
			listHandler(client, ctx, name)
		}
	}
}
