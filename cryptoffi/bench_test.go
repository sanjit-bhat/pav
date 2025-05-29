package cryptoffi

import (
	"crypto/sha256"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/mit-pdos/pav/benchutil"
)

func TestBenchRand32(t *testing.T) {
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)
	data := make([]byte, 32)

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
		{N: m1, Unit: "total(ms)"},
	})
}

func TestBenchRand64(t *testing.T) {
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
		{N: m1, Unit: "total(ms)"},
	})
}

func TestBenchHash(t *testing.T) {
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
		{N: m1, Unit: "total(ms)"},
	})
}

func TestBenchVrfProve(t *testing.T) {
	_, sk := VrfGenerateKey()
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)
	data := make([]byte, 16)

	nOps := 50_000
	start := time.Now()
	for i := 0; i < nOps; i++ {
		rnd.Read(data)
		sk.Prove(data)
	}
	total := time.Since(start)

	m0 := float64(total.Microseconds()) / float64(nOps)
	m1 := float64(total.Milliseconds())
	benchutil.Report(nOps, []*benchutil.Metric{
		{N: m0, Unit: "us/op"},
		{N: m1, Unit: "total(ms)"},
	})
}

func TestBenchVrfVerify(t *testing.T) {
	pk, sk := VrfGenerateKey()
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)
	data := make([]byte, 16)

	nOps := 50_000
	var total time.Duration
	for i := 0; i < nOps; i++ {
		rnd.Read(data)
		_, p := sk.Prove(data)

		t := time.Now()
		pk.Verify(data, p)
		total += time.Since(t)
	}

	m0 := float64(total.Microseconds()) / float64(nOps)
	m1 := float64(total.Milliseconds())
	benchutil.Report(nOps, []*benchutil.Metric{
		{N: m0, Unit: "us/op"},
		{N: m1, Unit: "total(ms)"},
	})
}

func TestBenchVrfSize(t *testing.T) {
	_, sk := VrfGenerateKey()
	data := make([]byte, 16)
	_, p := sk.Prove(data)
	benchutil.Report(0, []*benchutil.Metric{
		{N: float64(len(p)), Unit: "B"},
	})
}

func TestBenchSigGenVer(t *testing.T) {
	pk, sk := SigGenerateKey()
	data := make([]byte, 8+8+32)
	nOps := 200_000

	var totalGen time.Duration
	var totalVer time.Duration
	for i := 0; i < nOps; i++ {
		randRead(data)

		t0 := time.Now()
		sig := sk.Sign(data)

		t1 := time.Now()
		errb := pk.Verify(data, sig)
		if errb {
			t.Fatal()
		}
		t2 := time.Now()

		totalGen += t1.Sub(t0)
		totalVer += t2.Sub(t1)
	}

	m0 := float64(totalGen.Microseconds()) / float64(nOps)
	m1 := float64(totalGen.Milliseconds())
	m2 := float64(totalVer.Microseconds()) / float64(nOps)
	m3 := float64(totalVer.Milliseconds())
	benchutil.Report(nOps, []*benchutil.Metric{
		{N: m0, Unit: "us/op(gen)"},
		{N: m1, Unit: "total(ms,gen)"},
		{N: m2, Unit: "us/op(ver)"},
		{N: m3, Unit: "total(ms,ver)"},
	})
}

func lePutUint64(b []byte, v uint64) {
	_ = b[7] // early bounds check to guarantee safety of writes below
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	b[6] = byte(v >> 48)
	b[7] = byte(v >> 56)
}

func randRead(p []byte) {
	for len(p) >= 8 {
		lePutUint64(p, rand.Uint64())
		p = p[8:]
	}
	if len(p) > 0 {
		b := make([]byte, 8)
		lePutUint64(b, rand.Uint64())
		copy(p, b)
	}
}
