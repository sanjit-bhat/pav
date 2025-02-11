package merkle

import (
	"bytes"
	"github.com/mit-pdos/pav/benchutil"
	"github.com/mit-pdos/pav/cryptoffi"
	"math/rand/v2"
	"testing"
	"time"
)

var defVal = []byte("val")

const (
	defNSeed int = 1_000_000
)

func TestBenchMerkGet(t *testing.T) {
	tr, rnd := seedTree(t, defNSeed)
	label := make([]byte, cryptoffi.HashLen)
	nOps := 1_000_000

	start := time.Now()
	for i := 0; i < nOps; i++ {
		_, err := rnd.Read(label)
		if err != nil {
			t.Fatal(err)
		}
		// this gets non-memb.
		// memb has similar performance, as long as the
		// working set of labels is big enough (1M).
		_, _, errb := tr.Get(label)
		if errb {
			t.Fatal()
		}
	}
	total := time.Since(start)

	m0 := float64(total.Nanoseconds()) / float64(nOps)
	m1 := float64(total.Milliseconds())
	benchutil.Report(nOps, []*benchutil.Metric{
		{N: m0, Unit: "ns/op"},
		{N: m1, Unit: "total ms"},
	})
}

func TestBenchMerkProve(t *testing.T) {
	tr, rnd := seedTree(t, defNSeed)
	label := make([]byte, cryptoffi.HashLen)
	nOps := 1_000_000

	start := time.Now()
	for i := 0; i < nOps; i++ {
		_, err := rnd.Read(label)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, errb := tr.Prove(label)
		if errb {
			t.Fatal()
		}
	}
	total := time.Since(start)

	m0 := float64(total.Nanoseconds()) / float64(nOps)
	m1 := float64(total.Milliseconds())
	benchutil.Report(nOps, []*benchutil.Metric{
		{N: m0, Unit: "ns/op"},
		{N: m1, Unit: "total ms"},
	})
}

func TestBenchMerkPut(t *testing.T) {
	tr, rnd := seedTree(t, defNSeed)
	label := make([]byte, cryptoffi.HashLen)
	nOps := 200_000

	start := time.Now()
	for i := 0; i < nOps; i++ {
		_, err := rnd.Read(label)
		if err != nil {
			t.Fatal(err)
		}
		l := bytes.Clone(label)
		v := bytes.Clone(defVal)
		errb := tr.Put(l, v)
		if errb {
			t.Fatal()
		}
	}
	total := time.Since(start)

	m0 := float64(total.Nanoseconds()) / float64(nOps)
	m1 := float64(total.Milliseconds())
	benchutil.Report(nOps, []*benchutil.Metric{
		{N: m0, Unit: "ns/op"},
		{N: m1, Unit: "total ms"},
	})
}

func seedTree(t *testing.T, sz int) (tr *Tree, rnd *rand.ChaCha8) {
	tr = NewTree()
	var seed [32]byte
	rnd = rand.NewChaCha8(seed)

	for i := 0; i < sz; i++ {
		label := make([]byte, cryptoffi.HashLen)
		_, err := rnd.Read(label)
		if err != nil {
			t.Fatal(err)
		}
		v := bytes.Clone(defVal)
		errb := tr.Put(label, v)
		if errb {
			t.Fatal()
		}
	}
	return
}
