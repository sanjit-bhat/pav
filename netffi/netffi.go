package netffi

// Our net FFI started from the [gokv net FFI].
//
// [gokv net FFI]: https://github.com/mit-pdos/gokv/blob/05f31d837641498c3ca5d72f7ea9a6e6b2263e2c/grove_ffi/network.go

import (
	"fmt"
	"github.com/tchajed/marshal"
	"io"
	"net"
	"sync"
)

func AddressToStr(addr uint64) string {
	a0 := byte(addr & 0xff)
	addr = addr >> 8
	a1 := byte(addr & 0xff)
	addr = addr >> 8
	a2 := byte(addr & 0xff)
	addr = addr >> 8
	a3 := byte(addr & 0xff)
	addr = addr >> 8
	port := addr & 0xffff
	return fmt.Sprintf("%s:%d", net.IPv4(a0, a1, a2, a3).String(), port)
}

// # Conn

type Conn struct {
	c      net.Conn
	sendMu *sync.Mutex
	recvMu *sync.Mutex
}

func makeConn(conn net.Conn) *Conn {
	return &Conn{c: conn, sendMu: new(sync.Mutex), recvMu: new(sync.Mutex)}
}

// Dial returns new connection and errors on fail.
func Dial(addr uint64) (*Conn, bool) {
	conn, err := net.Dial("tcp", AddressToStr(addr))
	if err != nil {
		return nil, true
	}
	return makeConn(conn), false
}

func Send(c *Conn, data []byte) bool {
	// encoding: len(data) ++ data.
	e := marshal.NewEnc(8 + uint64(len(data)))
	e.PutInt(uint64(len(data)))
	e.PutBytes(data)
	msg := e.Finish()

	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	_, err := c.c.Write(msg)
	if err != nil {
		// prevent sending on this conn again.
		c.c.Close()
		return true
	}
	return false
}

// Receive returns data and errors on fail.
func Receive(c *Conn) ([]byte, bool) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	// encoding: len(data) ++ data.
	header := make([]byte, 8)
	_, err0 := io.ReadFull(c.c, header)
	if err0 != nil {
		// Looks like this connection is dead.
		// This can legitimately happen when the other side "hung up", so do not panic.
		// But also, we clearly lost track here of where in the protocol we are,
		// so close it.
		c.c.Close()
		return nil, true
	}
	d := marshal.NewDec(header)
	dataLen := d.GetInt()

	data := make([]byte, dataLen)
	_, err1 := io.ReadFull(c.c, data)
	if err1 != nil {
		// prevent sending on this conn again.
		c.c.Close()
		return nil, true
	}
	return data, false
}

// # Listener

type Listener struct {
	l net.Listener
}

func Listen(addr uint64) *Listener {
	l, err := net.Listen("tcp", AddressToStr(addr))
	if err != nil {
		// assume no Listen err. likely, port is already in use.
		panic(err)
	}
	return &Listener{l}
}

func Accept(l *Listener) *Conn {
	conn, err := l.l.Accept()
	if err != nil {
		// assume no Accept err.
		panic(err)
	}
	return makeConn(conn)
}
