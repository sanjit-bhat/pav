module example.com/secure-chat

go 1.20

replace example.com => ./

require (
	example.com v0.0.0-00010101000000-000000000000
	github.com/manifoldco/promptui v0.9.0
	google.golang.org/grpc v1.52.0
	google.golang.org/protobuf v1.28.1
)

require (
	github.com/chzyer/readline v0.0.0-20180603132655-2972be24d48e // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	golang.org/x/net v0.4.0 // indirect
	golang.org/x/sys v0.3.0 // indirect
	golang.org/x/text v0.5.0 // indirect
	google.golang.org/genproto v0.0.0-20221118155620-16455021b5e6 // indirect
)
