package alicebob

import (
	"net"
	"testing"
	"time"

	"github.com/sanjit-bhat/pav/ktcore"
	"github.com/sanjit-bhat/pav/server"
)

func init() {
	server.BatchTimeout = time.Millisecond
}

func TestAliceBob(t *testing.T) {
	if _, err := testAliceBob(makeUniqueAddr(), makeUniqueAddr()); err != ktcore.BlameNone {
		t.Fatal()
	}
}

func getFreePort() (port uint64, err error) {
	var a *net.TCPAddr
	if a, err = net.ResolveTCPAddr("tcp", "localhost:0"); err == nil {
		var l *net.TCPListener
		if l, err = net.ListenTCP("tcp", a); err == nil {
			defer l.Close()
			return uint64(l.Addr().(*net.TCPAddr).Port), nil
		}
	}
	return
}

func makeUniqueAddr() uint64 {
	port, err := getFreePort()
	if err != nil {
		panic("bad port")
	}
	// left shift to make IP 0.0.0.0.
	return port << 32
}
