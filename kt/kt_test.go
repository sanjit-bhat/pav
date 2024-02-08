package kt

import (
	"github.com/mit-pdos/gokv/grove_ffi"
	"testing"
	"time"
)

func TestAuditPass(t *testing.T) {
	addr := grove_ffi.MakeAddress("0.0.0.0:6060")
	go func() {
		s := NewKeyServ()
		s.Start(addr)
	}()
	serverStartup := 10 * time.Millisecond
	time.Sleep(serverStartup)
	testAuditPass(addr)
}

func TestAuditFail(t *testing.T) {
	addr1 := grove_ffi.MakeAddress("0.0.0.0:6060")
	addr2 := grove_ffi.MakeAddress("0.0.0.0:6061")
	go func() {
		s := NewKeyServ()
		s.Start(addr1)
	}()
	go func() {
		s := NewKeyServ()
		s.Start(addr2)
	}()
	serverStartup := 10 * time.Millisecond
	time.Sleep(serverStartup)
	addrs := []grove_ffi.Address{addr1, addr2}
	testAuditFail(addrs)
}
