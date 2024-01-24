package kv

import (
	"bytes"
	"fmt"
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/secure-chat/kv/ffi"
	"math/rand"
	"sync"
	"testing"
	"time"
)

func TestBasic(t *testing.T) {
	numClients := 2
	sks := make([]*ffi.SignerT, numClients)
	vks := make([]*ffi.VerifierT, numClients)
	for i := 0; i < numClients; i++ {
		sks[i], vks[i] = ffi.MakeKeys()
	}

	addr := grove_ffi.MakeAddress("0.0.0.0:6060")
	serverStartup := time.Millisecond
	s := ffi.MakeServer()
	s.Start(addr)

	var wg sync.WaitGroup
	oneDone := make(chan struct{}, 1)
	twoDone := make(chan struct{}, 1)
	k := uint64(3)
	v1 := []byte("v1")
	v2 := []byte("v2")

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
			t.Fail()
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
			t.Fail()
		}
		c.Put(k, v2)
		twoDone <- struct{}{}
	}()

	wg.Wait()
}

func TestManyOps(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping test in short mode")
    }
	numClients := 10
	numKeys := 10
	numVals := 10
	numOps := 1000

	sks := make([]*ffi.SignerT, numClients)
	vks := make([]*ffi.VerifierT, numClients)
	for i := 0; i < numClients; i++ {
		sks[i], vks[i] = ffi.MakeKeys()
	}
	vals := make([][]byte, numVals)
	for i := 0; i < numVals; i++ {
		vals[i] = []byte(fmt.Sprintf("v%d", i))
	}

    // Note: Go doesn't garbage collect server from other test, so use a diff addr.
	addr := grove_ffi.MakeAddress("0.0.0.0:6061")
	serverStartup := time.Millisecond
	s := ffi.MakeServer()
	s.Start(addr)

	var wg sync.WaitGroup
	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(cid int) {
			defer wg.Done()
			time.Sleep(serverStartup)
			c := MakeKvCli(addr, sks[cid], vks, uint64(cid))

			for opIdx := 0; opIdx < numOps; opIdx++ {
				if opIdx%100 == 0 {
					t.Log("cid", cid, "opIdx", opIdx)
				}
				k := uint64(rand.Intn(numKeys))
				op := rand.Intn(2)
				if op == 0 {
					c.Get(k)
				} else {
					v := vals[rand.Intn(numVals)]
					c.Put(k, v)
				}
			}
		}(i)
	}
	wg.Wait()
}
