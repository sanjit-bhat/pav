package main

import (
	"fmt"
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/secure-chat/full2"
	"github.com/mit-pdos/secure-chat/full2/fc_ffi"
	"github.com/mit-pdos/secure-chat/full2/shared"
	"github.com/tchajed/goose/machine"
	"sync"
	"time"
)

func main() {
	c := fc_ffi.Init()
	sA, vA, err := c.MakeKeys()
	machine.Assume(err == shared.ErrNone)
	sB, vB, err := c.MakeKeys()
	machine.Assume(err == shared.ErrNone)
	var vs = make([]*fc_ffi.VerifierT, 2)
	vs[shared.AliceNum] = vA
	vs[shared.BobNum] = vB

	addr := grove_ffi.MakeAddress("0.0.0.0:6060")
	var retA *shared.MsgT
	var retB *shared.MsgT
	aEvent := make(chan struct{})
	bEvent := make(chan struct{})
	serverStartup := 10 * time.Millisecond

	var wg sync.WaitGroup
	go func() {
		s := fc_ffi.MakeServer()
		s.Start(addr)
	}()
	wg.Add(1)
	go func() {
		time.Sleep(serverStartup)
		a := full2.MakeAlice(addr, sA, vs)
		a.One()
		aEvent <- struct{}{}

		<-bEvent
		retA = a.Two()
		wg.Done()
	}()
	wg.Add(1)
	go func() {
		time.Sleep(serverStartup)
		<-aEvent
		b := full2.MakeBob(addr, sB, vs)
		retB = b.One()
		bEvent <- struct{}{}
		wg.Done()
	}()
	wg.Wait()

	fmt.Println("retA:", retA)
	fmt.Println("retB:", retB)
	machine.Assert(retA != nil && retB != nil && retA.Equals(retB))
}
