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
	inMap, val, proof := m.Prove(label)
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
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)

	for i := 0; i < 100; i++ {
		l := make([]byte, cryptoffi.HashLen)
		v := make([]byte, 4)
		rnd.Read(l)
		rnd.Read(v)
		inMap, _, p := m.Prove(l)
		if inMap {
			t.Fatal()
		}

		dOld := m.Hash()
		m.Put(l, v)
		dNew := m.Hash()

		dOld0, dNew0, err := VerifyUpdate(l, v, p)
		if err {
			t.Fatal()
		}
		if !bytes.Equal(dOld, dOld0) {
			t.Fatal()
		}
		if !bytes.Equal(dNew, dNew0) {
			t.Fatal()
		}
	}
}
