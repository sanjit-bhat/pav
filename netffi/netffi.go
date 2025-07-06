package netffi

// This net FFI started from [grove].
// It provides a TCP-like network for testing, although its formal model
// is a network where [Conn.Send] might not deliver bytes,
// and [Conn.Receive] returns arbitrary bytes.
//
// [grove]: https://github.com/mit-pdos/gokv/blob/05f31d837641498c3ca5d72f7ea9a6e6b2263e2c/grove_ffi/network.go

import (
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/tchajed/marshal"
)

func addrToStr(addr uint64) string {
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

// Dial returns new connection.
func Dial(addr uint64) *Conn {
	conn, err := net.Dial("tcp", addrToStr(addr))
	if err != nil {
		// hard for client's to recover if there's an addr err, so fail loudly.
		panic("netffi: Dial err")
	}
	return newConn(conn)
}

func (c *Conn) Send(data []byte) bool {
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

func newConn(conn net.Conn) *Conn {
	return &Conn{c: conn, sendMu: new(sync.Mutex), recvMu: new(sync.Mutex)}
}

func (c *Conn) Receive() (data []byte, err bool) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	// encoding: len(data) ++ data.
	header := make([]byte, 8)
	if _, errg := io.ReadFull(c.c, header); errg != nil {
		// Looks like this connection is dead.
		// This can legitimately happen when the other side "hung up", so do not panic.
		// But also, we clearly lost track here of where in the protocol we are,
		// so close it.
		c.c.Close()
		err = true
		return
	}
	d := marshal.NewDec(header)
	dataLen := d.GetInt()

	data = make([]byte, dataLen)
	if _, errg := io.ReadFull(c.c, data); errg != nil {
		// prevent sending on this conn again.
		c.c.Close()
		err = true
		return
	}
	return data, false
}

// # Listener

type Listener struct {
	l net.Listener
}

func Listen(addr uint64) *Listener {
	l, err := net.Listen("tcp", addrToStr(addr))
	if err != nil {
		// assume no Listen err. likely, port is already in use.
		panic("netffi: Listen err")
	}
	return &Listener{l}
}

func (l *Listener) Accept() *Conn {
	conn, err := l.l.Accept()
	if err != nil {
		// assume no Accept err.
		panic("netffi: Accept err")
	}
	return newConn(conn)
}
