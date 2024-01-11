package main

import (
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/secure-chat/kv"
	"github.com/mit-pdos/secure-chat/kv/ffi"
	"github.com/mit-pdos/secure-chat/kv/shared"
	"github.com/tchajed/goose/machine"
	"sync"
	"time"
)

func main() {
	c := ffi.Init()
	sA, vA, err := c.MakeKeys()
	machine.Assert(err == shared.ErrNone)
	sB, vB, err := c.MakeKeys()
	machine.Assert(err == shared.ErrNone)
	vs := []*ffi.VerifierT{vA, vB}

	addr := grove_ffi.MakeAddress("0.0.0.0:6060")
	serverStartup := 10 * time.Millisecond

	var wg sync.WaitGroup
	go func() {
		s := ffi.MakeServer()
		s.Start(addr)
	}()
	oneDone := make(chan struct{}, 1)
	twoDone := make(chan struct{}, 1)
	k := uint64(3)
	v := uint64(11)

	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(serverStartup)
		c := kv.MakeKvCli(addr, sA, vs, 0)

		c.Put(k, v)
		oneDone <- struct{}{}

		<-twoDone
		v2 := c.Get(k)
		machine.Assert(v+1 == v2)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(serverStartup)
		c := kv.MakeKvCli(addr, sB, vs, 1)

		<-oneDone
		v2 := c.Get(k)
		c.Put(k, v2+1)
		twoDone <- struct{}{}
	}()

	wg.Wait()
}
