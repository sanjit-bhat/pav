package kt

import (
	"bytes"
	"github.com/mit-pdos/pav/benchutil"
	"github.com/mit-pdos/pav/cryptoffi"
	"math/rand/v2"
	"testing"
	"time"
)

var defVal = []byte{2}

const (
	nSeed int = 1_000_000
)

func TestBenchPut(t *testing.T) {
	serv, rnd, vrfPk := seedServer()
	nOps := 2_000

	start := time.Now()
	for i := 0; i < nOps; i++ {
		u := rnd.Uint64()
		v := bytes.Clone(defVal)
		dig, lat, bound := serv.Put(u, v)
		if checkMemb(vrfPk, u, 0, dig.Dig, lat) {
			t.Fatal()
		}
		if checkNonMemb(vrfPk, u, 1, dig.Dig, bound) {
			t.Fatal()
		}
	}
	total := time.Since(start)

	m0 := float64(total.Microseconds()) / float64(nOps)
	m1 := float64(total.Milliseconds())
	benchutil.Report(nOps, []*benchutil.Metric{
		{N: m0, Unit: "us/op"},
		{N: m1, Unit: "total ms"},
	})
}

func seedServer() (*Server, *rand.ChaCha8, *cryptoffi.VrfPublicKey) {
	serv, _, vrfPk := NewServer()
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)

	els := make(map[uint64][]byte, nSeed)
	for i := 0; i < nSeed; i++ {
		u := rnd.Uint64()
		v := bytes.Clone(defVal)
		els[u] = v
	}
	serv.PutBatch(els, false)
	return serv, rnd, vrfPk
}
