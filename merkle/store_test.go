package merkle

import (
	"bytes"
	"math/rand/v2"
	"testing"

	"github.com/sanjit-bhat/pav/cryptoffi"
)

// memStore stands in for the KV store, and counts what a real one would
// charge for: probes issued and probes that hit. records live in fixed slots
// in one arena, keyed by a fixed-size array, so the harness costs a map probe
// and a copy per hit rather than a string allocation per probe -- the copy is
// what a real client pays anyway, and the allocation is not.
const slotSize = 1 + 1 + cryptoffi.HashLen + 40 // length, tag, label, value

// the arena is chunked, since one slice big enough for tens of millions of
// records cannot be grown by doubling on a box this size.
const chunkSlots = 1 << 20

type memStore struct {
	idx    map[[StoreKeyLen]byte]uint64
	chunks [][]byte
	used   uint64
	probes int
	hits   int
}

func newMemStore() *memStore {
	return &memStore{idx: make(map[[StoreKeyLen]byte]uint64)}
}

func (s *memStore) slot(i uint64) []byte {
	c := s.chunks[i/chunkSlots]
	off := (i % chunkSlots) * slotSize
	return c[off : off+slotSize]
}

func (s *memStore) put(keys, recs [][]byte) {
	for i, k := range keys {
		rec := recs[i]
		if uint64(len(rec)) >= slotSize {
			panic("record does not fit a slot")
		}
		var key [StoreKeyLen]byte
		copy(key[:], k)
		at, ok := s.idx[key]
		if !ok {
			if s.used/chunkSlots == uint64(len(s.chunks)) {
				s.chunks = append(s.chunks, make([]byte, chunkSlots*slotSize))
			}
			at = s.used
			s.used++
			s.idx[key] = at
		}
		sl := s.slot(at)
		sl[0] = byte(len(rec))
		copy(sl[1:], rec)
	}
}

func (s *memStore) get1(k []byte) []byte {
	s.probes++
	var key [StoreKeyLen]byte
	copy(key[:], k)
	at, ok := s.idx[key]
	if !ok {
		return nil
	}
	s.hits++
	sl := s.slot(at)
	return bytes.Clone(sl[1 : 1+uint64(sl[0])])
}

// get is the one batch read a path costs.
func (s *memStore) get(keys [][]byte) [][]byte {
	out := make([][]byte, len(keys))
	for i, k := range keys {
		out[i] = s.get1(k)
	}
	return out
}

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

// loadBatch loads every label's path with one deduped batch read, which is
// what a writer does with an epoch and a reader does with one label. paths
// that outran maxD cost a second, much smaller read.
func (s *memStore) loadBatch(t *testing.T, m *Map, labels [][]byte, maxD uint64) {
	seen := make(map[[StoreKeyLen]byte]int, len(labels)*int(maxD))
	var keys [][]byte
	pks := make([][][]byte, len(labels))
	minDs := make([]uint64, len(labels))
	var kb [StoreKeyLen]byte
	for i, l := range labels {
		minD, pk, needed := m.PathNeeds(l, maxD)
		if !needed {
			continue
		}
		minDs[i], pks[i] = minD, pk
		for _, k := range pk {
			copy(kb[:], k)
			if _, ok := seen[kb]; !ok {
				seen[kb] = len(keys)
				keys = append(keys, k)
			}
		}
	}
	if len(keys) == 0 {
		return
	}
	got := s.get(keys)

	var deep [][]byte
	for i, l := range labels {
		if pks[i] == nil {
			continue
		}
		recs := make([][]byte, len(pks[i]))
		for j, k := range pks[i] {
			copy(kb[:], k)
			recs[j] = got[seen[kb]]
		}
		complete, err := m.LoadPath(l, minDs[i], recs)
		if err {
			t.Fatal("load")
		}
		if !complete {
			deep = append(deep, l)
		}
	}
	if len(deep) > 0 {
		if maxD == maxDepth {
			t.Fatal("path past maxDepth")
		}
		s.loadBatch(t, m, deep, min(maxD+probeExtend, maxDepth))
	}
}

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
	tape, err := oc.Update(newLabels, newVals)
	if err {
		t.Fatal()
	}
	if _, err := mem.Update(newLabels, newVals); err {
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
		bad.put([][]byte{keys[i]}, [][]byte{tampered})

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
	if _, err := m.Update(labels[:1], vals[:1]); !err {
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
	tape, err := oc.Update(newLabels, newVals)
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

func TestEvictPath(t *testing.T) {
	mem := &Map{}
	labels, vals := mkSeeded(20_000, 6)
	if _, err := mem.Update(labels, vals); err {
		t.Fatal()
	}
	dig := mem.Hash()
	store := newMemStore()
	store.put(mem.Records())

	// evicting one path must leave the digest alone and must leave every
	// other loaded path where it was.
	m := NewCut(dig)
	for i := 0; i < 50; i++ {
		store.loadFrom(t, m, labels[i], 30)
	}
	if !bytes.Equal(m.Hash(), dig) {
		t.Fatal()
	}
	m.EvictPath(labels[0], 8)
	if !bytes.Equal(m.Hash(), dig) {
		t.Fatal("evict changed the digest")
	}
	if _, _, _, err := m.Prove(labels[0]); !err {
		t.Fatal("evicted path still answered")
	}
	for i := 1; i < 50; i++ {
		if _, _, _, err := m.Prove(labels[i]); err {
			// a sibling path may share the evicted sub-tree, so only
			// require that reloading it works.
			store.loadFrom(t, m, labels[i], 30)
		}
		inMap, val, proof, err := m.Prove(labels[i])
		if err || !inMap {
			t.Fatal("reload after evict")
		}
		h, err := VerifyMemb(labels[i], val, proof)
		if err || !bytes.Equal(h, dig) {
			t.Fatal()
		}
	}
}

// TestReplicaLoop runs the read replica's actual protocol over several epochs:
// rebuild the map from the epoch's audit proof, check it against the digest,
// evict to bound it, then serve lookups by loading only the records below the
// warm top and shedding each path afterwards.
func TestReplicaLoop(t *testing.T) {
	const keepD = 10
	const probeD = 34

	store := newMemStore()
	writer := &Map{}
	dig := writer.Hash()
	var all [][]byte

	var warm *Map
	for ep := 0; ep < 5; ep++ {
		labels, vals := mkSeeded(4_000, byte(20+ep))
		all = append(all, labels...)
		digOld := dig
		tape, err := writer.Update(labels, vals)
		if err {
			t.Fatal()
		}
		store.put(writer.Records())
		dig = writer.Hash()

		// the replica sees only (labels, vals, tape) and the old digest.
		m, hOld, err := ApplyUpdate(labels, vals, tape)
		if err || !bytes.Equal(hOld, digOld) || !bytes.Equal(m.Hash(), dig) {
			t.Fatalf("epoch %d did not apply", ep)
		}
		m.Evict(keepD)
		if !bytes.Equal(m.Hash(), dig) {
			t.Fatal("evict changed the digest")
		}
		warm = m

		// serve against every label inserted so far, including ones from
		// epochs this replica has since evicted.
		for i := 0; i < 300; i++ {
			l := all[rand.IntN(len(all))]
			store.loadFrom(t, warm, l, probeD)
			inMap, val, proof, err := warm.Prove(l)
			if err || !inMap {
				t.Fatalf("epoch %d lookup", ep)
			}
			h, err := VerifyMemb(l, val, proof)
			if err || !bytes.Equal(h, dig) {
				t.Fatalf("epoch %d proof against the wrong digest", ep)
			}
			warm.EvictPath(l, keepD)
			if !bytes.Equal(warm.Hash(), dig) {
				t.Fatal("serving a lookup changed the digest")
			}
		}

		// an absent label must come back absent, against the same digest.
		absent := make([]byte, cryptoffi.HashLen)
		copy(absent, all[0])
		absent[0] ^= 0x55
		store.loadFrom(t, warm, absent, probeD)
		inMap, _, proof, err := warm.Prove(absent)
		if err || inMap {
			t.Fatal("absent label")
		}
		h, err := VerifyNonMemb(absent, proof)
		if err || !bytes.Equal(h, dig) {
			t.Fatal()
		}
		warm.EvictPath(absent, keepD)
	}
}
