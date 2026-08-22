package merkle

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"testing"

	"github.com/sanjit-bhat/pav/cryptoffi"
)

func TestGetRecent(t *testing.T) {
	m := &Map{}
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)
	label := make([]byte, cryptoffi.HashLen)
	val := make([]byte, 4)

	for i := 0; i < 100_000; i++ {
		rnd.Read(label)
		rnd.Read(val)

		// initially, label shouldn't be there.
		proveAndVerify(t, m, label, false, nil)

		l := bytes.Clone(label)
		v := bytes.Clone(val)
		m.Put(l, v)

		// after put, (label, val) should be there.
		proveAndVerify(t, m, label, true, val)
	}
}

func TestMap(t *testing.T) {
	m := &Map{}
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)
	label := make([]byte, cryptoffi.HashLen)
	val := make([]byte, 4)
	truth := make(map[string][]byte, 100_000)

	// init map and truth.
	for i := 0; i < 100_000; i++ {
		rnd.Read(label)
		rnd.Read(val)

		l0 := bytes.Clone(label)
		v0 := bytes.Clone(val)
		m.Put(l0, v0)

		v1 := bytes.Clone(val)
		truth[string(label)] = v1
	}

	// test everything in map.
	for l0, v0 := range truth {
		proveAndVerify(t, m, []byte(l0), true, v0)
	}
}

func proveAndVerify(t *testing.T, m *Map, label []byte, expInMap bool, expVal []byte) {
	inMap, val, proof, _ := m.Prove(label)
	if inMap != expInMap {
		t.Fatal()
	}
	if inMap && !bytes.Equal(val, expVal) {
		t.Fatal()
	}
	hash := m.Hash()
	var hash0 []byte
	var err bool
	if inMap {
		hash0, err = VerifyMemb(label, val, proof)
	} else {
		hash0, err = VerifyNonMemb(label, proof)
	}
	if err {
		t.Fatal()
	}
	if !bytes.Equal(hash, hash0) {
		t.Fatal()
	}
}

func TestUpdate(t *testing.T) {
	m := &Map{}
	truth := &Map{}
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)

	// batch sizes spanning "smaller than the tree's branching factor" to
	// "denser than the tree", against a tree that keeps growing.
	for _, batch := range []int{1, 2, 3, 10, 1000, 10_000, 1, 5000} {
		labels := make([][]byte, 0, batch)
		vals := make([][]byte, 0, batch)
		for i := 0; i < batch; i++ {
			l := make([]byte, cryptoffi.HashLen)
			v := make([]byte, 4)
			rnd.Read(l)
			rnd.Read(v)
			labels = append(labels, l)
			vals = append(vals, v)
			truth.Put(bytes.Clone(l), bytes.Clone(v))
		}

		dOld := m.Hash()
		p, err := m.Update(labels, vals)
		if err {
			t.Fatal()
		}
		dNew := m.Hash()
		if !bytes.Equal(dNew, truth.Hash()) {
			t.Fatal("batch update disagrees with one-at-a-time put")
		}

		dOld0, dNew0, err := VerifyUpdate(labels, vals, p)
		if err {
			t.Fatal()
		}
		if !bytes.Equal(dOld, dOld0) || !bytes.Equal(dNew, dNew0) {
			t.Fatal()
		}

		// every inserted entry must now prove out against the new digest.
		for i, l := range labels {
			proveAndVerify(t, m, l, true, vals[i])
		}
	}
}

func TestUpdateReject(t *testing.T) {
	m := &Map{}
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)
	mk := func(n int) ([][]byte, [][]byte) {
		labels := make([][]byte, 0, n)
		vals := make([][]byte, 0, n)
		for i := 0; i < n; i++ {
			l := make([]byte, cryptoffi.HashLen)
			v := make([]byte, 4)
			rnd.Read(l)
			rnd.Read(v)
			labels = append(labels, l)
			vals = append(vals, v)
		}
		return labels, vals
	}

	labels, vals := mk(1000)
	p, err := m.Update(labels, vals)
	if err {
		t.Fatal()
	}

	// re-inserting a label already in the map.
	if _, err := m.Update([][]byte{bytes.Clone(labels[0])}, [][]byte{{9}}); !err {
		t.Fatal("re-insert accepted")
	}
	// a batch that repeats a label.
	l2, v2 := mk(1)
	if _, err := m.Update([][]byte{l2[0], bytes.Clone(l2[0])}, [][]byte{v2[0], v2[0]}); !err {
		t.Fatal("duplicate in batch accepted")
	}

	// a verifier must reject a tape whose leaves were altered, a truncated
	// tape, and a tape with trailing garbage.
	bad := bytes.Clone(p)
	bad[len(bad)-1] ^= 1
	if _, dNew, err := VerifyUpdate(labels, vals, bad); !err && bytes.Equal(dNew, m.Hash()) {
		t.Fatal("altered tape verified to the same digest")
	}
	if _, _, err := VerifyUpdate(labels, vals, p[:len(p)-1]); !err {
		t.Fatal("truncated tape accepted")
	}
	if _, _, err := VerifyUpdate(labels, vals, append(bytes.Clone(p), 0)); !err {
		t.Fatal("trailing garbage accepted")
	}
	// a wrong batch against a good tape need not error, but it must not
	// reach the digest the server signed.
	if _, dNew, err := VerifyUpdate(labels[:1], vals[:1], p); !err && bytes.Equal(dNew, m.Hash()) {
		t.Fatal("wrong batch reached the right digest")
	}
}

// TestUpdateTamper is the property the auditor leans on: no altered tape and
// no altered batch reaches both the old digest the auditor already trusts and
// a new digest, except the one the server actually produced.
func TestUpdateTamper(t *testing.T) {
	m := &Map{}
	var seed [32]byte
	seed[0] = 7
	rnd := rand.NewChaCha8(seed)
	mk := func(n int) ([][]byte, [][]byte) {
		ls := make([][]byte, 0, n)
		vs := make([][]byte, 0, n)
		for i := 0; i < n; i++ {
			l := make([]byte, cryptoffi.HashLen)
			v := make([]byte, 32)
			rnd.Read(l)
			rnd.Read(v)
			ls = append(ls, l)
			vs = append(vs, v)
		}
		return ls, vs
	}

	labels, vals := mk(20_000)
	if _, err := m.Update(labels, vals); err {
		t.Fatal()
	}
	dOld := m.Hash()
	newLabels, newVals := mk(500)
	tape, err := m.Update(cloneAll(newLabels), cloneAll(newVals))
	if err {
		t.Fatal()
	}
	dNew := m.Hash()

	accept := func(ls, vs [][]byte, p []byte) bool {
		o, n, err := VerifyUpdate(ls, vs, p)
		return !err && bytes.Equal(o, dOld) && bytes.Equal(n, dNew)
	}
	if !accept(newLabels, newVals, tape) {
		t.Fatal("the real proof did not verify")
	}

	var b [8]byte
	for i := 0; i < 3_000; i++ {
		rnd.Read(b[:])
		pos := int(binary.LittleEndian.Uint64(b[:]) % uint64(len(tape)))
		bit := byte(1) << (b[0] % 8)
		bad := bytes.Clone(tape)
		bad[pos] ^= bit
		if accept(newLabels, newVals, bad) {
			t.Fatalf("altered tape byte %d accepted", pos)
		}
	}
	// a batch the server did not insert must not reach dNew either.
	for i := 0; i < 500; i++ {
		rnd.Read(b[:])
		j := int(binary.LittleEndian.Uint64(b[:]) % uint64(len(newLabels)))
		bad := cloneAll(newVals)
		bad[j] = bytes.Clone(bad[j])
		bad[j][0] ^= 1
		if accept(newLabels, bad, tape) {
			t.Fatal("altered value accepted")
		}
		badL := cloneAll(newLabels)
		badL[j] = bytes.Clone(badL[j])
		badL[j][0] ^= 1
		if accept(badL, newVals, tape) {
			t.Fatal("altered label accepted")
		}
	}
	// dropping or repeating an entry must not reach dNew.
	if accept(newLabels[:len(newLabels)-1], newVals[:len(newVals)-1], tape) {
		t.Fatal("short batch accepted")
	}
	if accept(append(cloneAll(newLabels), newLabels[0]),
		append(cloneAll(newVals), newVals[0]), tape) {
		t.Fatal("repeated entry accepted")
	}
}

func TestUpdateEdges(t *testing.T) {
	// an empty batch against an empty map, and against a one-leaf map.
	m := &Map{}
	d0 := m.Hash()
	p, err := m.Update(nil, nil)
	if err {
		t.Fatal()
	}
	if o, n, err := VerifyUpdate(nil, nil, p); err || !bytes.Equal(o, d0) || !bytes.Equal(n, d0) {
		t.Fatal("empty batch on an empty map")
	}

	l := make([]byte, cryptoffi.HashLen)
	l[0] = 3
	p, err = m.Update([][]byte{bytes.Clone(l)}, [][]byte{{1}})
	if err {
		t.Fatal()
	}
	d1 := m.Hash()
	if o, n, err := VerifyUpdate([][]byte{l}, [][]byte{{1}}, p); err ||
		!bytes.Equal(o, d0) || !bytes.Equal(n, d1) {
		t.Fatal("first leaf")
	}
	// the map is now a bare leaf at depth 0, so the tape is one leaf record.
	p, err = m.Update(nil, nil)
	if err {
		t.Fatal()
	}
	if o, n, err := VerifyUpdate(nil, nil, p); err || !bytes.Equal(o, d1) || !bytes.Equal(n, d1) {
		t.Fatal("empty batch on a one-leaf map")
	}

	// an out-of-core map that is entirely a cut still takes an empty batch,
	// since nothing reaches the cut.
	oc := NewCut(d1)
	p, err = oc.Update(nil, nil)
	if err {
		t.Fatal("empty batch on a cut map")
	}
	if o, n, err := VerifyUpdate(nil, nil, p); err || !bytes.Equal(o, d1) || !bytes.Equal(n, d1) {
		t.Fatal()
	}

	// an empty value is a value.
	l2 := make([]byte, cryptoffi.HashLen)
	l2[0] = 200
	if _, err := m.Update([][]byte{bytes.Clone(l2)}, [][]byte{{}}); err {
		t.Fatal()
	}
	inMap, v, mp, err := m.Prove(l2)
	if err || !inMap || len(v) != 0 {
		t.Fatal("empty value")
	}
	if h, err := VerifyMemb(l2, v, mp); err || !bytes.Equal(h, m.Hash()) {
		t.Fatal()
	}
}
