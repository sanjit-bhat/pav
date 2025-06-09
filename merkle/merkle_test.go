package merkle

import (
	"bytes"
	"math/rand/v2"
	"testing"

	"github.com/mit-pdos/pav/cryptoffi"
)

func TestGetRecent(t *testing.T) {
	tr := NewTree()
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)
	label := make([]byte, cryptoffi.HashLen)
	val := make([]byte, 4)

	for i := 0; i < 100_000; i++ {
		rnd.Read(label)
		rnd.Read(val)

		// initially, label shouldn't be there.
		proveAndVerify(t, tr, label, false, nil)

		l := bytes.Clone(label)
		v := bytes.Clone(val)
		errb := tr.Put(l, v)
		if errb {
			t.Fatal()
		}

		// after put, (label, val) should be there.
		proveAndVerify(t, tr, label, true, val)
	}
}

func TestMap(t *testing.T) {
	tr := NewTree()
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)
	label := make([]byte, cryptoffi.HashLen)
	val := make([]byte, 4)
	m := make(map[string][]byte, 100_000)

	// init map and tree.
	for i := 0; i < 100_000; i++ {
		rnd.Read(label)
		rnd.Read(val)

		l0 := bytes.Clone(label)
		v0 := bytes.Clone(val)
		errb := tr.Put(l0, v0)
		if errb {
			t.Fatal()
		}

		v1 := bytes.Clone(val)
		m[string(label)] = v1
	}

	// test everything in map.
	for l0, v0 := range m {
		proveAndVerify(t, tr, []byte(l0), true, v0)
	}
}

func proveAndVerify(t *testing.T, tr *Tree, label []byte, expInTree bool, expVal []byte) {
	inTree, val, proof := tr.Prove(label)
	if inTree != expInTree {
		t.Fatal()
	}
	if !bytes.Equal(val, expVal) {
		t.Fatal()
	}
	dig := tr.Digest()
	var dig0 []byte
	var err bool
	if inTree {
		dig0, err = VerifyMemb(label, val, proof)
	} else {
		dig0, err = VerifyNonMemb(label, proof)
	}
	if err {
		t.Fatal()
	}
	if !bytes.Equal(dig, dig0) {
		t.Fatal()
	}
}

func TestUpdate(t *testing.T) {
	tr := NewTree()
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)

	for i := 0; i < 100; i++ {
		l := make([]byte, cryptoffi.HashLen)
		v := make([]byte, 4)
		rnd.Read(l)
		rnd.Read(v)
		inTree, _, p := tr.Prove(l)
		if inTree {
			t.Fatal()
		}

		dOld := tr.Digest()
		if tr.Put(l, v) {
			t.Fatal()
		}
		dNew := tr.Digest()

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
