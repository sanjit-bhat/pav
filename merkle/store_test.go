package merkle

import (
	"bytes"
	"math/rand/v2"
	"testing"

	"github.com/sanjit-bhat/pav/cryptoffi"
)

// memStore stands in for the KV store, and counts what a real one would
// charge for: probes issued and probes that hit.
type memStore struct {
	m      map[string][]byte
	probes int
	hits   int
}

func newMemStore() *memStore { return &memStore{m: make(map[string][]byte)} }

func (s *memStore) put(keys, recs [][]byte) {
	for i, k := range keys {
		s.m[string(k)] = recs[i]
	}
}

func (s *memStore) get1(key []byte) []byte {
	s.probes++
	v, ok := s.m[string(key)]
	if ok {
		s.hits++
	}
	return v
}

// get is the one batch read a path costs.
func (s *memStore) get(keys [][]byte) [][]byte {
	out := make([][]byte, len(keys))
	for i, k := range keys {
		s.probes++
		v, ok := s.m[string(k)]
		if ok {
			s.hits++
			out[i] = v
		}
	}
	return out
}

// loadFrom loads label's path, asking the map which records it needs and
// extending the probe if the bound was short.
func (s *memStore) loadFrom(t *testing.T, m *Map, label []byte, maxD uint64) {
	for {
		minD, keys, needed := m.PathNeeds(label, maxD)
		if !needed {
			return
		}
		complete, err := m.LoadPath(label, minD, s.get(keys))
		if err {
			t.Fatal("load")
		}
		if complete {
			return
		}
		if maxD == maxDepth {
			t.Fatal("path past maxDepth")
		}
		maxD = min(maxD+probeExtend, maxDepth)
	}
}

// probeExtend is how much deeper to probe when a path outruns the bound.
const probeExtend uint64 = 16

func TestStoreRoundTrip(t *testing.T) {
	const n = 20_000
	const probeD = 40

	// build in core, then spill every node to the store.
	mem := &Map{}
	labels, vals := mkSeeded(n, 1)
	if _, err := mem.Update(labels, vals); err {
		t.Fatal()
	}
	dig := mem.Hash()
	store := newMemStore()
	store.put(mem.Records())

	// every leaf must prove out of the store alone, as must an absent label,
	// each from one path load.
	for i := 0; i < 500; i++ {
		l := labels[rand.IntN(n)]
		m := NewCut(dig)
		store.loadFrom(t, m, l, probeD)
		inMap, val, proof, err := m.Prove(l)
		if err || !inMap {
			t.Fatal("membership")
		}
		h, err := VerifyMemb(l, val, proof)
		if err || !bytes.Equal(h, dig) {
			t.Fatal("verify membership")
		}

		absent := make([]byte, cryptoffi.HashLen)
		copy(absent, l)
		absent[31] ^= 0x80
		m2 := NewCut(dig)
		store.loadFrom(t, m2, absent, probeD)
		inMap, _, proof, err = m2.Prove(absent)
		if err || inMap {
			t.Fatal("non-membership")
		}
		h, err = VerifyNonMemb(absent, proof)
		if err || !bytes.Equal(h, dig) {
			t.Fatal("verify non-membership")
		}
	}

	// an epoch update done entirely out of core must reach the same digest as
	// the in-core one, and must leave the store able to serve the new tree.
	newLabels, newVals := mkSeeded(2_000, 2)
	oc := NewCut(dig)
	for _, l := range newLabels {
		store.loadFrom(t, oc, l, probeD)
	}
	tape, err := oc.Update(cloneAll(newLabels), cloneAll(newVals))
	if err {
		t.Fatal()
	}
	if _, err := mem.Update(cloneAll(newLabels), cloneAll(newVals)); err {
		t.Fatal()
	}
	if !bytes.Equal(oc.Hash(), mem.Hash()) {
		t.Fatal("out-of-core update disagrees with in-core")
	}
	dOld, dNew, err := VerifyUpdate(newLabels, newVals, tape)
	if err || !bytes.Equal(dOld, dig) || !bytes.Equal(dNew, mem.Hash()) {
		t.Fatal("tape from an out-of-core update")
	}

	store.put(oc.Records())
	dig = mem.Hash()
	for i := 0; i < 200; i++ {
		l := newLabels[rand.IntN(len(newLabels))]
		m := NewCut(dig)
		store.loadFrom(t, m, l, probeD)
		inMap, val, proof, err := m.Prove(l)
		if err || !inMap {
			t.Fatal("membership after out-of-core update")
		}
		h, err := VerifyMemb(l, val, proof)
		if err || !bytes.Equal(h, dig) {
			t.Fatal()
		}
	}
}

func TestStoreReject(t *testing.T) {
	mem := &Map{}
	labels, vals := mkSeeded(1_000, 3)
	if _, err := mem.Update(labels, vals); err {
		t.Fatal()
	}
	dig := mem.Hash()
	keys, recs := mem.Records()

	// a store that returns a record not matching the cut it fills must be
	// caught, wherever on the path it sits.
	for _, i := range []int{0, len(recs) / 2, len(recs) - 1} {
		bad := newMemStore()
		bad.put(keys, recs)
		tampered := bytes.Clone(recs[i])
		tampered[len(tampered)-1] ^= 1
		bad.m[string(keys[i])] = tampered

		var caught bool
		for _, l := range labels {
			m := NewCut(dig)
			if _, err := m.LoadPath(l, 0, bad.get(PathKeys(l, 0, 40))); err {
				caught = true
				break
			}
		}
		if !caught {
			t.Fatal("tampered record went unnoticed")
		}
	}

	// an unloaded path must error rather than answer.
	m := NewCut(dig)
	if _, _, _, err := m.Prove(labels[0]); !err {
		t.Fatal("proved from a cut")
	}
	if _, err := m.Update(cloneAll(labels[:1]), cloneAll(vals[:1])); !err {
		t.Fatal("updated into a cut")
	}
}

func mkSeeded(n int, seed byte) (labels, vals [][]byte) {
	var s [32]byte
	s[0] = seed
	rnd := rand.NewChaCha8(s)
	labels = make([][]byte, 0, n)
	vals = make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		l := make([]byte, cryptoffi.HashLen)
		v := make([]byte, 32)
		rnd.Read(l)
		rnd.Read(v)
		labels = append(labels, l)
		vals = append(vals, v)
	}
	return
}

func cloneAll(xs [][]byte) [][]byte {
	out := make([][]byte, len(xs))
	copy(out, xs)
	return out
}

// TestWarmFromTape is the read-replica path: a party that only has the epoch's
// audit proof ends up holding the new tree's top, self-checked against the
// digest, and can then serve lookups by loading only the deep records.
func TestWarmFromTape(t *testing.T) {
	const n = 50_000
	const probeD = 40

	mem := &Map{}
	labels, vals := mkSeeded(n, 4)
	if _, err := mem.Update(labels, vals); err {
		t.Fatal()
	}
	digOld := mem.Hash()
	store := newMemStore()
	store.put(mem.Records())

	newLabels, newVals := mkSeeded(5_000, 5)
	oc := NewCut(digOld)
	for _, l := range newLabels {
		store.loadFrom(t, oc, l, probeD)
	}
	tape, err := oc.Update(cloneAll(newLabels), cloneAll(newVals))
	if err {
		t.Fatal()
	}
	store.put(oc.Records())
	dig := oc.Hash()

	// the replica sees only (labels, vals, tape).
	warm, hOld, err := ApplyUpdate(newLabels, newVals, tape)
	if err || !bytes.Equal(hOld, digOld) || !bytes.Equal(warm.Hash(), dig) {
		t.Fatal("apply")
	}
	const keepD = 12
	warm.Evict(keepD)
	if !bytes.Equal(warm.Hash(), dig) {
		t.Fatal("evict changed the digest")
	}

	cold := NewCut(dig)
	var warmProbes, coldProbes int
	for i := 0; i < 500; i++ {
		l := labels[rand.IntN(n)]

		before := store.probes
		store.loadFrom(t, warm, l, probeD)
		inMap, val, proof, err := warm.Prove(l)
		if err || !inMap {
			t.Fatal("warm lookup")
		}
		h, err := VerifyMemb(l, val, proof)
		if err || !bytes.Equal(h, dig) {
			t.Fatal()
		}
		warmProbes += store.probes - before
		warm.Evict(keepD)

		before = store.probes
		store.loadFrom(t, cold, l, probeD)
		if _, _, _, err := cold.Prove(l); err {
			t.Fatal("cold lookup")
		}
		coldProbes += store.probes - before
		cold = NewCut(dig)
	}
	if warmProbes >= coldProbes {
		t.Fatalf("warm map probed %d, cold %d", warmProbes, coldProbes)
	}
	t.Logf("probes/lookup: warm %.1f, cold %.1f",
		float64(warmProbes)/500, float64(coldProbes)/500)
}
