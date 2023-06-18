proto:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		internal/protoDefs/chat.proto

keys:
	go run internal/setupKeys/main.go

server:
	go run server/main.go

client:
	go run client/main.go

server-race:
	go run -race server/main.go

client-race:
	go run -race client/main.go
