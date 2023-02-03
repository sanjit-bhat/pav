package main

import (
	"context"
	"log"
	"time"

	pb "example.com/rpc"
	"github.com/manifoldco/promptui"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func putHandler(client pb.SharerClient, name string, msg string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	log.Println("Putting a msg onto the server")
	resp, err := client.PutPhoto(ctx, &pb.PutPhotoReq{Name: name, Data: msg})
	if err != nil {
		log.Fatalln("could not put photo:", err)
	}
	log.Println("File is saved under:", resp.GetFile())
}

func listHandler(client pb.SharerClient, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
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
		_, op, err := prompt.Run()
		if err != nil {
			log.Println("Prompt failed", err)
			continue
		}

		switch op{
		case "End":
			return
		case "Put":
			prompt := promptui.Prompt{
				Label: "Msg",
			}
			msg, err := prompt.Run()
			if err != nil {
				log.Println("Prompt failed", err)
				continue
			}
			putHandler(client, name, msg)
		case "List":
			listHandler(client, name)
		}
	}
}
