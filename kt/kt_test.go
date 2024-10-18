package kt

import (
	"net"
	"testing"
)

func TestAll(t *testing.T) {
	serverAddr := makeUniqueAddr()
	adtr0Addr := makeUniqueAddr()
	adtr1Addr := makeUniqueAddr()
	testAll(serverAddr, adtr0Addr, adtr1Addr)
}

func TestBasic(t *testing.T) {
	servAddr := makeUniqueAddr()
	adtr0Addr := makeUniqueAddr()
	adtr1Addr := makeUniqueAddr()
	p := setup(servAddr, adtr0Addr, adtr1Addr)
	testBasic(p)
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
