package merkle

import (
	"bytes"
	"math"
	"math/rand/v2"
	"runtime"
	"testing"
	"time"

	"github.com/aclements/go-moremath/stats"
	"github.com/sanjit-bhat/pav/benchutil"
)

const (
	defNSeed uint64 = 1_000_000
	// probeSlack sets the path probe bound at log2(N) + probeSlack. leaf depth
	// is log2(N) + Geom(1/2), so a 2^-probeSlack tail probes deeper.
	probeSlack uint64 = 6
)

func probeBound(n uint64) uint64 {
	var d uint64
	for 1<<d < n {
		d++
	}
	return d + probeSlack
}

func TestBenchMerkPut(t *testing.T) {
	m, _ := seedMap(defNSeed)
	nOps := 500_000

	start := time.Now()
	for i := 0; i < nOps; i++ {
		l := mkRandLabel()
		v := mkRandVal()
		m.Put(l, v)
	}
	total := time.Since(start)

	m0 := float64(total.Microseconds()) / float64(nOps)
	m1 := float64(total.Milliseconds())
	benchutil.Report(nOps, []*benchutil.Metric{
		{N: m0, Unit: "us/op"},
		{N: m1, Unit: "total(ms)"},
	})
}

func TestBenchMerkGenVer(t *testing.T) {
	m, labels := seedMap(defNSeed)
	nOps := 5_000_000

	var totalGen time.Duration
	var totalVer time.Duration
	for i := 0; i < nOps; i++ {
		l := labels[rand.Uint64N(defNSeed)]

		t0 := time.Now()
		isReg, v, p, _ := m.Prove(l)
		if !isReg {
			t.Fatal()
		}
		d := m.Hash()

		t1 := time.Now()
		d0, _ := VerifyMemb(l, v, p)
		bytes.Equal(d, d0)
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

func TestBenchMerkSize(t *testing.T) {
	m, labels := seedMap(defNSeed)
	samp := &stats.Sample{Xs: make([]float64, 0, defNSeed)}
	for _, label := range labels {
		isReg, _, p, _ := m.Prove(label)
		if !isReg {
			t.Fatal()
		}
		samp.Xs = append(samp.Xs, float64(len(p)))
	}
	benchutil.Report(1, []*benchutil.Metric{
		{N: math.Round(samp.Mean()), Unit: "B"},
	})
}

func seedMap(sz uint64) (m *Map, labels [][]byte) {
	m = &Map{}
	labels = make([][]byte, 0, sz)
	const chunk = 100_000
	for done := uint64(0); done < sz; done += chunk {
		n := min(chunk, sz-done)
		ls, vs := mkBatch(n)
		labels = append(labels, ls...)
		if _, err := m.Update(ls, vs); err {
			panic("seed")
		}
	}
	return
}

func mkBatch(n uint64) (labels, vals [][]byte) {
	labels = make([][]byte, 0, n)
	vals = make([][]byte, 0, n)
	for i := uint64(0); i < n; i++ {
		labels = append(labels, mkRandLabel())
		vals = append(vals, mkRandVal())
	}
	return
}

// TestBenchMerkEpoch is the etc/ workload: an epoch is one batch of ~46k
// insertions into a tree that already holds nSeed leaves.
func TestBenchMerkEpoch(t *testing.T) {
	m, _ := seedMap(defNSeed)
	const batch = 46_000
	nEpochs := 10

	var totalUpd, totalVer time.Duration
	var totalProof int
	dig := m.Hash()
	for i := 0; i < nEpochs; i++ {
		labels, vals := mkBatch(batch)
		t0 := time.Now()
		p, err := m.Update(labels, vals)
		if err {
			t.Fatal()
		}
		t1 := time.Now()
		digNew := m.Hash()

		dOld, dNew, err := VerifyUpdate(labels, vals, p)
		if err {
			t.Fatal()
		}
		t2 := time.Now()
		if !bytes.Equal(dOld, dig) || !bytes.Equal(dNew, digNew) {
			t.Fatal()
		}
		dig = digNew

		totalUpd += t1.Sub(t0)
		totalVer += t2.Sub(t1)
		totalProof += len(p)
	}

	nOps := batch * nEpochs
	benchutil.Report(nOps, []*benchutil.Metric{
		{N: float64(totalUpd.Microseconds()) / float64(nOps), Unit: "us/op(upd)"},
		{N: float64(totalVer.Microseconds()) / float64(nOps), Unit: "us/op(ver)"},
		{N: float64(totalProof) / float64(nOps), Unit: "B/op(proof)"},
		{N: float64(totalUpd.Milliseconds()) / float64(nEpochs), Unit: "ms/epoch"},
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

func mkRandLabel() []byte {
	x := make([]byte, 32)
	randRead(x)
	return x
}

func mkRandVal() []byte {
	x := make([]byte, 40)
	randRead(x)
	return x
}

// TestBenchMerkStoreGet measures what a lookup costs a KV store: one batch
// read of computable keys, and how many of them hit.
func TestBenchMerkStoreGet(t *testing.T) {
	m, labels := seedMap(defNSeed)
	dig := m.Hash()
	store := newMemStore()
	store.put(m.Records())
	m = nil
	runtime.GC()

	nOps := 20_000
	var bytesRead int
	var totalGen time.Duration
	for i := 0; i < nOps; i++ {
		l := labels[rand.Uint64N(defNSeed)]
		t0 := time.Now()
		oc := NewCut(dig)
		before := store.hits
		store.loadFrom(t, oc, l, probeBound(defNSeed))
		bytesRead += (store.hits - before) * 65
		inMap, _, _, err := oc.Prove(l)
		if err || !inMap {
			t.Fatal()
		}
		totalGen += time.Since(t0)
	}

	benchutil.Report(nOps, []*benchutil.Metric{
		{N: float64(store.probes) / float64(nOps), Unit: "probes/op"},
		{N: float64(store.hits) / float64(nOps), Unit: "hits/op"},
		{N: float64(bytesRead) / float64(nOps), Unit: "B/op(read)"},
		{N: float64(totalGen.Microseconds()) / float64(nOps), Unit: "us/op(cpu)"},
	})
}

// TestBenchMerkStoreEpoch measures what one epoch costs a KV store: the
// deduped prefix probe for the whole batch, then the records it writes back.
func TestBenchMerkStoreEpoch(t *testing.T) {
	m, _ := seedMap(defNSeed)
	dig := m.Hash()
	store := newMemStore()
	store.put(m.Records())
	m = nil
	runtime.GC()

	const batch = 46_000
	nEpochs := 3
	var bytesRead, bytesWrit, nWrit int
	var totalLoad, totalUpd time.Duration
	for i := 0; i < nEpochs; i++ {
		labels, vals := mkBatch(batch)

		t0 := time.Now()
		oc := NewCut(dig)
		// the whole batch's keys are computable up front, so this is one
		// batch read. dedup, since the top of the tree is shared.
		seen := make(map[string]bool, batch*probeBound(defNSeed))
		var keys [][]byte
		for _, l := range labels {
			for _, k := range PathKeys(l, probeBound(defNSeed)) {
				if !seen[string(k)] {
					seen[string(k)] = true
					keys = append(keys, k)
				}
			}
		}
		got := store.get(keys)
		fetched := make(map[string][]byte, len(keys))
		for j, k := range keys {
			if got[j] != nil {
				fetched[string(k)] = got[j]
				bytesRead += len(got[j])
			}
		}
		for _, l := range labels {
			pk := PathKeys(l, probeBound(defNSeed))
			recs := make([][]byte, len(pk))
			for j, k := range pk {
				recs[j] = fetched[string(k)]
			}
			complete, err := oc.LoadPath(l, recs)
			if err {
				t.Fatal("load")
			}
			if !complete {
				// the rare path past the bound: a second, tiny round trip.
				store.loadFrom(t, oc, l, probeBound(defNSeed)+probeExtend)
			}
		}
		t1 := time.Now()

		if _, err := oc.Update(labels, vals); err {
			t.Fatal("update")
		}
		wk, wr := oc.Records()
		t2 := time.Now()
		store.put(wk, wr)
		dig = oc.Hash()

		nWrit += len(wk)
		for _, r := range wr {
			bytesWrit += len(r) + int(StoreKeyLen)
		}
		totalLoad += t1.Sub(t0)
		totalUpd += t2.Sub(t1)
	}

	nOps := batch * nEpochs
	benchutil.Report(nOps, []*benchutil.Metric{
		{N: float64(store.probes) / float64(nOps), Unit: "probes/op"},
		{N: float64(store.hits) / float64(nOps), Unit: "hits/op"},
		{N: float64(nWrit) / float64(nOps), Unit: "writes/op"},
		{N: float64(bytesRead) / float64(nOps), Unit: "B/op(read)"},
		{N: float64(bytesWrit) / float64(nOps), Unit: "B/op(writ)"},
		{N: float64(totalLoad.Microseconds()) / float64(nOps), Unit: "us/op(load)"},
		{N: float64(totalUpd.Microseconds()) / float64(nOps), Unit: "us/op(upd)"},
	})
}
