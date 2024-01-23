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
	numUsers := 2
	sks := make([]*ffi.SignerT, numUsers)
	vks := make([]*ffi.VerifierT, numUsers)
	for i := 0; i < numUsers; i++ {
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
	// TODO: will Go garbage collect the server thread here?
}

func TestPorcupine(t *testing.T) {
	numUsers := 10
	numKeys := 10
	numVals := 10
	numOps := 1000

	sks := make([]*ffi.SignerT, numUsers)
	vks := make([]*ffi.VerifierT, numUsers)
	for i := 0; i < numUsers; i++ {
		sks[i], vks[i] = ffi.MakeKeys()
	}
	vals := make([][]byte, numVals)
	for i := 0; i < numVals; i++ {
		vals[i] = []byte(fmt.Sprintf("v%d", i))
	}

	addr := grove_ffi.MakeAddress("0.0.0.0:6061")
	serverStartup := time.Millisecond
	s := ffi.MakeServer()
	s.Start(addr)

	var wg sync.WaitGroup
	for i := 0; i < numUsers; i++ {
		wg.Add(1)
		go func(uid int) {
			defer wg.Done()
			time.Sleep(serverStartup)
			c := MakeKvCli(addr, sks[uid], vks, uint64(uid))

			for opIdx := 0; opIdx < numOps; opIdx++ {
				if opIdx%100 == 0 {
					fmt.Println("uid", uid, "opIdx", opIdx)
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
