package kt2

import (
	"math/rand/v2"
	"testing"
)

func TestAll(t *testing.T) {
	serverAddr := makeUniqueAddr()
	adtr0Addr := makeUniqueAddr()
	adtr1Addr := makeUniqueAddr()
	testAll(serverAddr, adtr0Addr, adtr1Addr)
}

func makeUniqueAddr() uint64 {
	port := uint64(rand.IntN(4000)) + 6000
	// left shift to make IP 0.0.0.0.
	return port << 32
}
