package kt

import (
	"fmt"
	"github.com/mit-pdos/gokv/grove_ffi"
	"math/rand/v2"
	"testing"
)

func makeUniqueAddr() uint64 {
	port := rand.IntN(4000) + 6000
	ip := fmt.Sprintf("0.0.0.0:%d", port)
	addr := grove_ffi.MakeAddress(ip)
	return addr
}

func TestAgreement(t *testing.T) {
	servAddr := makeUniqueAddr()
	adtr0Addr := makeUniqueAddr()
	adtr1Addr := makeUniqueAddr()
	testAgreement(servAddr, adtr0Addr, adtr1Addr)
}
