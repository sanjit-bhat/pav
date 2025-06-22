package alicebob

import (
	"net"
	"testing"

	"github.com/mit-pdos/pav/ktcore"
)

func TestAliceBob(t *testing.T) {
	servAddr := makeUniqueAddr()
	adtrAddrs := []uint64{makeUniqueAddr(), makeUniqueAddr()}
	err := testAliceBob(servAddr, adtrAddrs)
	if err.Err != ktcore.BlameNone {
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
