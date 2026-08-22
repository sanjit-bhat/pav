package merkle

import (
	"bytes"
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
