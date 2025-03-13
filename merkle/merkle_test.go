package merkle

import (
	"bytes"
	"github.com/mit-pdos/pav/cryptoffi"
	"math/rand/v2"
	"testing"
)

func TestGetRecent(t *testing.T) {
	tr := NewTree()
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)
	label := make([]byte, cryptoffi.HashLen)
	val := make([]byte, 4)

	for i := 0; i < 1_000_000; i++ {
		_, err := rnd.Read(label)
		if err != nil {
			t.Fatal(err)
		}
		_, err = rnd.Read(val)
		if err != nil {
			t.Fatal(err)
		}

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
	m := make(map[string][]byte, 1_000_000)

	// init map and tree.
	for i := 0; i < 1_000_000; i++ {
		_, err := rnd.Read(label)
		if err != nil {
			t.Fatal(err)
		}
		_, err = rnd.Read(val)
		if err != nil {
			t.Fatal(err)
		}

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
	inTree, val, proof, errb := tr.Prove(label)
	if errb {
		t.Fatal()
	}
	if inTree != expInTree {
		t.Fatal()
	}
	if !bytes.Equal(val, expVal) {
		t.Fatal()
	}
	dig := tr.Digest()
	errb = Verify(inTree, label, val, proof, dig)
	if errb {
		t.Fatal()
	}
}
