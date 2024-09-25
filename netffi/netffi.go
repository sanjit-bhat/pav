package netffi

// Our net FFI started from the [gokv net FFI].
//
// [gokv net FFI]: https://github.com/mit-pdos/gokv/blob/05f31d837641498c3ca5d72f7ea9a6e6b2263e2c/grove_ffi/network.go

import (
	"fmt"
	"github.com/tchajed/marshal"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
)

func MakeAddress(ipStr string) uint64 {
	// TODO: manually parsing is pretty silly; couldn't figure out how to make
	// this work cleanly net.IP
	ipPort := strings.Split(ipStr, ":")
	if len(ipPort) != 2 {
		panic(fmt.Sprintf("Not ipv4:port %s", ipStr))
	}
	port, err := strconv.ParseUint(ipPort[1], 10, 16)
	if err != nil {
		panic(err)
	}

	ss := strings.Split(ipPort[0], ".")
	if len(ss) != 4 {
		panic(fmt.Sprintf("Not ipv4:port %s", ipStr))
	}
	ip := make([]byte, 4)
	for i, s := range ss {
		a, err := strconv.ParseInt(s, 10, 8)
		if err != nil {
			panic(err)
		}
		ip[i] = byte(a)
	}
	return (uint64(ip[0]) | uint64(ip[1])<<8 | uint64(ip[2])<<16 | uint64(ip[3])<<24 | uint64(port)<<32)
}

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
	conn net.Conn
	// guarding *sending* on [conn].
	sendMu *sync.Mutex
	// guarding *receiving* on [conn].
	recvMu *sync.Mutex
}

func makeConn(conn net.Conn) *Conn {
	return &Conn{conn: conn, sendMu: new(sync.Mutex), recvMu: new(sync.Mutex)}
}

// Dial returns new connection and error on fail.
func Dial(addr uint64) (*Conn, bool) {
	conn, err := net.Dial("tcp", AddressToStr(addr))
	if err != nil {
		return nil, true
	}
	return makeConn(conn), false
}

func Send(c *Conn, data []byte) bool {
	// Encode message
	e := marshal.NewEnc(8 + uint64(len(data)))
	e.PutInt(uint64(len(data)))
	e.PutBytes(data)
	msg := e.Finish()

	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	// message format: [dataLen] ++ data
	// Writing in a single call is faster than 2 calls despite the unnecessary copy.
	_, err := c.conn.Write(msg)
	// If there was an error, make sure we never send anything on this channel again...
	// there might have been a partial write!
	if err != nil {
		c.conn.Close()
	}
	return err != nil
}

// Receive returns data and error on fail.
func Receive(c *Conn) ([]byte, bool) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	// message format: [dataLen] ++ data
	header := make([]byte, 8)
	_, err := io.ReadFull(c.conn, header)
	if err != nil {
		// Looks like this connection is dead.
		// This can legitimately happen when the other side "hung up", so do not panic.
		// But also, we clearly lost track here of where in the protocol we are,
		// so close it.
		c.conn.Close()
		return nil, true
	}
	d := marshal.NewDec(header)
	dataLen := d.GetInt()

	data := make([]byte, dataLen)
	_, err2 := io.ReadFull(c.conn, data)
	if err2 != nil {
		// See other comment.
		c.conn.Close()
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
		// Assume() no error on Listen.
		// This should fail loud and early, retrying makes little sense
		// (likely the port is already used).
		panic(err)
	}
	return &Listener{l}
}

func Accept(l *Listener) *Conn {
	conn, err := l.l.Accept()
	if err != nil {
		// This should not usually happen... something seems wrong.
		panic(err)
	}

	return makeConn(conn)
}
