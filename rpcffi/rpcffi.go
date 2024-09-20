package rpcffi

import (
	"github.com/mit-pdos/gokv/grove_ffi"
	"net"
	"net/http"
	"net/rpc"
)

type errorT = bool

// TODO: Goose doesn't support any.
func Serve(rcvr any, addr grove_ffi.Address) errorT {
	err := rpc.Register(rcvr)
	if err != nil {
		return true
	}
	rpc.HandleHTTP()
	l, err := net.Listen("tcp", grove_ffi.AddressToStr(addr))
	if err != nil {
		return true
	}
	go http.Serve(l, nil)
	return false
}

type Client struct {
	c *rpc.Client
}

func NewClient(addr grove_ffi.Address) (*Client, errorT) {
	c, err := rpc.DialHTTP("tcp", grove_ffi.AddressToStr(addr))
	if err != nil {
		return nil, true
	}
	return &Client{c: c}, false
}

// TODO: Goose doesn't support any.
func (c *Client) Call(method string, args any, reply any) errorT {
	return c.c.Call(method, args, reply) != nil
}
