package chat4

import (
	"sync"

	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/tchajed/marshal"
)

type errorT = bool
type rpcIdT = uint64

const (
	ERRNONE bool   = false
	ERRSOME bool   = true
	RPCGET  rpcIdT = 1
	RPCPUT  rpcIdT = 2
)

func encodeUint64(data uint64) []byte {
	return marshal.WriteInt(make([]byte, 0), data)
}

func decodeUint64(data []byte) uint64 {
	out, _ := marshal.ReadInt(data)
	return out
}

func rpcCall(rpcId rpcIdT, in []byte, out []byte) errorT {
	return ERRNONE
}

type aliceRet struct {
	err    errorT
	passed bool
}

func aliceMain() aliceRet {
	cr := grove_ffi.Connect(addr)
	if cr.Err {
		return aliceRet{err: ERRSOME, passed: false}
	}
	conn := cr.Connection

	r1 := grove_ffi.Receive(conn)
	if r1.Err {
		return aliceRet{err: ERRSOME, passed: false}
	}
	snOrig := decodeUint64(r1.Data)

	r2 := grove_ffi.Receive(conn)
	if r2.Err {
		return aliceRet{err: ERRSOME, passed: false}
	}
	snLater := decodeUint64(r2.Data)

	snEq := snOrig == snLater
	return aliceRet{err: ERRNONE, passed: snEq}
}

func bobMain(addr grove_ffi.Address) errorT {
	cr := grove_ffi.Connect(addr)
	if cr.Err {
		return ERRSOME
	}
	conn := cr.Connection

	r1 := grove_ffi.Receive(conn)
	if r1.Err {
		return ERRSOME
	}

	return grove_ffi.Send(conn, r1.Data)
}

func serverMain(addr grove_ffi.Address) errorT {
	ln := grove_ffi.Listen(addr)
	// TODO: need to know that alice was the first connection.
	// Or, alice/bob announce themselves as the first msg on the channel.
	connAlice := grove_ffi.Accept(ln)
	connBob := grove_ffi.Accept(ln)

	snOrig := uint64(87294)
	snOrigB := encodeUint64(snOrig)
	err1 := grove_ffi.Send(connAlice, snOrigB)
	if err1 {
		return ERRSOME
	}
	err2 := grove_ffi.Send(connBob, snOrigB)
	if err2 {
		return ERRSOME
	}

	snLater := grove_ffi.Receive(connBob)
	if snLater.Err {
		return ERRSOME
	}
	err3 := grove_ffi.Send(connAlice, snLater.Data)
	if err3 {
		return ERRSOME
	}

	return ERRNONE
}

func RunAll(addr grove_ffi.Address) {
	//var wg sync.WaitGroup
	wg := new(sync.WaitGroup)
	wg.Add(3)
	go func() {
		serverMain(addr)
		wg.Done()
	}()
	go func() {
		aliceMain(addr)
		wg.Done()
	}()
	go func() {
		bobMain(addr)
		wg.Done()
	}()
	wg.Wait()
}
