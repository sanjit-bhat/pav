package main

import (
	"context"
	"log"
	"time"

	pb "example.com/chatGrpc"
	"github.com/manifoldco/promptui"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func putHandler(client pb.ChatClient, name string, msg string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	log.Println("Putting a msg onto the server")
	_, err := client.PutMsg(ctx, &pb.PutMsgReq{Name: name, Msg: msg})
	if err != nil {
		log.Fatalln("could not put photo:", err)
	}
}

func listHandler(client pb.ChatClient, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	log.Println("Getting a list of photos on the server")
	resp, err := client.GetMsgs(ctx, &pb.GetMsgsReq{Name: name})
	if err != nil {
		log.Fatalln("failed to list photos:", err)
	}
	log.Println("Available photos:", resp.GetMsgs())
}

func main() {
	addr := "localhost:50051"
	name := "sanjit"

	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalln("failed to connect:", err)
	}
	defer conn.Close()
	client := pb.NewChatClient(conn)

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
