package merkle

import (
	"bytes"
	"crypto/sha256"
	"github.com/mit-pdos/pav/benchutil"
	"github.com/mit-pdos/pav/cryptoffi"
	"math/rand/v2"
	"testing"
	"time"
)

var val = []byte("val")

const (
	nSeed int = 1_000_000
)

func TestBenchRand(t *testing.T) {
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)
	data := make([]byte, 64)

	nOps := 100_000_000
	start := time.Now()
	for i := 0; i < nOps; i++ {
		rnd.Read(data)
	}
	total := time.Since(start)

	m0 := float64(total.Nanoseconds()) / float64(nOps)
	m1 := float64(total.Milliseconds())
	benchutil.Report(nOps, []*benchutil.Metric{
		{N: m0, Unit: "ns/op"},
		{N: m1, Unit: "total ms"},
	})
}

func TestBenchRandHash(t *testing.T) {
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)
	data := make([]byte, 64)

	nOps := 10_000_000
	start := time.Now()
	for i := 0; i < nOps; i++ {
		rnd.Read(data)
		sha256.Sum256(data)
	}
	total := time.Since(start)

	m0 := float64(total.Nanoseconds()) / float64(nOps)
	m1 := float64(total.Milliseconds())
	benchutil.Report(nOps, []*benchutil.Metric{
		{N: m0, Unit: "ns/op"},
		{N: m1, Unit: "total ms"},
	})
}

func TestBenchGet(t *testing.T) {
	tr, rnd := setup(t, nSeed)
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

func TestBenchProve(t *testing.T) {
	tr, rnd := setup(t, nSeed)
	label := make([]byte, cryptoffi.HashLen)
	nOps := 1_000_000

	start := time.Now()
	for i := 0; i < nOps; i++ {
		_, err := rnd.Read(label)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, _, errb := tr.Prove(label)
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

func TestBenchPut(t *testing.T) {
	tr, rnd := setup(t, nSeed)
	label := make([]byte, cryptoffi.HashLen)
	nOps := 200_000

	start := time.Now()
	for i := 0; i < nOps; i++ {
		_, err := rnd.Read(label)
		if err != nil {
			t.Fatal(err)
		}
		l := bytes.Clone(label)
		v := bytes.Clone(val)
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

func setup(t *testing.T, sz int) (tr *Tree, rnd *rand.ChaCha8) {
	tr = NewTree()
	var seed [32]byte
	rnd = rand.NewChaCha8(seed)

	for i := 0; i < sz; i++ {
		label := make([]byte, cryptoffi.HashLen)
		_, err := rnd.Read(label)
		if err != nil {
			t.Fatal(err)
		}
		v := bytes.Clone(val)
		errb := tr.Put(label, v)
		if errb {
			t.Fatal()
		}
	}
	return
}
