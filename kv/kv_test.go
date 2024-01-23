package kv

import (
	"bytes"
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/secure-chat/kv/ffi"
	"sync"
	"testing"
	"time"
)

func TestBasic(t *testing.T) {
	c := ffi.Init()
	numUsers := 2
	sks := make([]*ffi.SignerT, numUsers)
	vks := make([]*ffi.VerifierT, numUsers)
	for i := 0; i < numUsers; i++ {
		sks[i], vks[i] = c.MakeKeys()
	}

	addr := grove_ffi.MakeAddress("0.0.0.0:6060")
	serverStartup := time.Millisecond
	s := ffi.MakeServer()
	s.Start(addr)

	var wg sync.WaitGroup
	oneDone := make(chan struct{}, 1)
	twoDone := make(chan struct{}, 1)
	k := uint64(3)
	v1 := []byte("value1")
	v2 := []byte("value2")

	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(serverStartup)
		c := MakeKvCli(addr, sks[0], vks, 0)

		c.Put(k, v1)
		oneDone <- struct{}{}

		<-twoDone
		v3 := c.Get(k)
		if !bytes.Equal(v2, v3) {
			t.Errorf("fail")
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(serverStartup)
		c := MakeKvCli(addr, sks[1], vks, 1)

		<-oneDone
		v3 := c.Get(k)
		if !bytes.Equal(v1, v3) {
			t.Errorf("fail")
		}
		c.Put(k, v2)
		twoDone <- struct{}{}
	}()

	wg.Wait()
	// TODO: will Go garbage collect the server thread here?
}
