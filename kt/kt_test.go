package kt

import (
	"fmt"
	"github.com/mit-pdos/gokv/grove_ffi"
	"sync"
	"testing"
)

var port = 6060
var portMu = new(sync.Mutex)

func makeUniqueAddr() uint64 {
	portMu.Lock()
	ip := fmt.Sprintf("0.0.0.0:%d", port)
	addr := grove_ffi.MakeAddress(ip)
	port++
	portMu.Unlock()
	return addr
}

func TestAgreement(t *testing.T) {
	servAddr := makeUniqueAddr()
	adtr0Addr := makeUniqueAddr()
	adtr1Addr := makeUniqueAddr()
	testAgreement(servAddr, adtr0Addr, adtr1Addr)
}
