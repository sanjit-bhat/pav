package main

import (
	"github.com/mit-pdos/gokv/grove_ffi"
    "github.com/mit-pdos/secure-chat/chat4"
)

func main() {
    addr := grove_ffi.MakeAddress("0.0.0.0:8394")
    chat4.RunAll(addr)
}
