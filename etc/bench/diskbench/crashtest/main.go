// crashtest kills a writer in the middle of an epoch and then asks whether the
// store is still consistent with the digest that survived.
//
// it exists because design A's node keys are *mutable*: a node's record is
// overwritten by every epoch that touches it. under MVCC that is harmless, and
// "write the records, then write HEAD" is a sound epoch commit whose atomic
// step is one key. on a single-version store it is not, and this shows the
// difference rather than arguing it.
//
//	seed        build a tree, commit epoch 0
//	epoch       apply one more epoch, optionally SIGKILL mid-way
//	verify      read HEAD, decide which epoch it names, and check that every
//	            committed label still proves out against it
package main

import (
	"bytes"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"syscall"

	"github.com/cockroachdb/pebble"
	"github.com/sanjit-bhat/pav/merkle"
)

var (
	dir    = flag.String("dir", "/var/tmp/crashtest", "LSM directory")
	phase  = flag.String("phase", "verify", "seed | epoch | verify")
	batch  = flag.Int("batch", 20_000, "leaves per epoch")
	nEpoch = flag.Int("epochs", 3, "how many epochs the sequence has, for verify")
	which  = flag.Int("which", 1, "which epoch to apply, for phase=epoch")
	mode   = flag.String("commit", "atomic", "atomic | headlast")
	crash  = flag.String("crash", "", "mid | after | (empty for a clean run)")
)

const maxD = 40

var headKey = append(make([]byte, merkle.StoreKeyLen-1), 0xff)

// labels for epoch k, deterministic so every phase agrees on them.
func epochLabels(k, n int) (labels, vals [][]byte) {
	var seed [32]byte
	seed[0] = byte(k + 1)
	rnd := rand.NewChaCha8(seed)
	for i := 0; i < n; i++ {
		l := make([]byte, 32)
		v := make([]byte, 32)
		rnd.Read(l)
		rnd.Read(v)
		labels = append(labels, l)
		vals = append(vals, v)
	}
	return
}

// digests replays the whole sequence in memory, so verify knows every digest a
// correct store is allowed to be showing.
func digests(nEpochs, n int) (digs [][]byte) {
	m := &merkle.Map{}
	digs = append(digs, m.Hash())
	for k := 0; k < nEpochs; k++ {
		l, v := epochLabels(k, n)
		if _, err := m.Update(l, v); err {
			panic("replay")
		}
		digs = append(digs, m.Hash())
	}
	return
}

type store struct {
	db     *pebble.DB
	probes int
}

func (s *store) get(keys [][]byte) [][]byte {
	out := make([][]byte, len(keys))
	for i, k := range keys {
		s.probes++
		v, closer, err := s.db.Get(k)
		if err == pebble.ErrNotFound {
			continue
		}
		if err != nil {
			panic(err)
		}
		out[i] = append([]byte(nil), v...)
		closer.Close()
	}
	return out
}

func (s *store) commit(keys, vals [][]byte, opts *pebble.WriteOptions) {
	b := s.db.NewBatch()
	for i, k := range keys {
		if err := b.Set(k, vals[i], nil); err != nil {
			panic(err)
		}
	}
	if err := b.Commit(opts); err != nil {
		panic(err)
	}
}

// load fills m with every label's path, or reports the first store record that
// does not match the cut it was supposed to fill.
func load(s *store, m *merkle.Map, labels [][]byte) error {
	for _, l := range labels {
		for {
			minD, keys, needed := m.PathNeeds(l, maxD)
			if !needed {
				break
			}
			complete, err := m.LoadPath(l, minD, s.get(keys))
			if err {
				return fmt.Errorf("record does not match the cut it fills, on %x", l[:4])
			}
			if complete {
				break
			}
			return fmt.Errorf("path past %d on %x", maxD, l[:4])
		}
	}
	return nil
}

func main() {
	flag.Parse()
	db, err := pebble.Open(*dir, &pebble.Options{Cache: pebble.NewCache(64 << 20)})
	if err != nil {
		panic(err)
	}
	s := &store{db: db}

	switch *phase {
	case "seed":
		labels, vals := epochLabels(0, *batch)
		m := &merkle.Map{}
		if _, e := m.Update(labels, vals); e {
			panic("seed")
		}
		k, v := m.Records()
		s.commit(append(k, headKey), append(v, m.Hash()), pebble.Sync)
		fmt.Printf("seeded epoch 0, digest %x\n", m.Hash()[:8])
		db.Close()

	case "epoch":
		v, closer, err := db.Get(headKey)
		if err != nil {
			panic(err)
		}
		dig := append([]byte(nil), v...)
		closer.Close()
		labels, vals := epochLabels(*which, *batch)
		m := merkle.NewCut(dig)
		if err := load(s, m, labels); err != nil {
			panic(err)
		}
		if _, e := m.Update(labels, vals); e {
			panic("update")
		}
		wk, wv := m.Records()
		newDig := m.Hash()

		if *mode == "headlast" {
			s.commit(wk, wv, pebble.NoSync)
			if *crash == "mid" {
				fmt.Println("kill -9: records written, HEAD not")
				syscall.Kill(syscall.Getpid(), syscall.SIGKILL)
			}
			s.commit([][]byte{headKey}, [][]byte{newDig}, pebble.Sync)
		} else {
			if *crash == "mid" {
				// atomic: there is no "records written, HEAD not" state to
				// crash in, so the nearest thing is dying before the commit.
				fmt.Println("kill -9: before the atomic commit")
				syscall.Kill(syscall.Getpid(), syscall.SIGKILL)
			}
			s.commit(append(wk, headKey), append(wv, newDig), pebble.Sync)
		}
		if *crash == "after" {
			fmt.Println("kill -9: right after the commit")
			syscall.Kill(syscall.Getpid(), syscall.SIGKILL)
		}
		fmt.Printf("epoch %d committed, digest %x\n", *which, newDig[:8])
		db.Close()

	case "verify":
		v, closer, err := db.Get(headKey)
		if err != nil {
			fmt.Println("FAIL: no HEAD")
			os.Exit(1)
		}
		dig := append([]byte(nil), v...)
		closer.Close()

		digs := digests(*nEpoch, *batch)
		at := -1
		for i, d := range digs {
			if bytes.Equal(d, dig) {
				at = i
			}
		}
		if at < 0 {
			fmt.Printf("FAIL: HEAD %x is not any epoch's digest\n", dig[:8])
			os.Exit(1)
		}
		fmt.Printf("HEAD names epoch %d, digest %x\n", at, dig[:8])

		// every label committed by epoch `at` must still prove out, and every
		// label of the epoch after it must prove absent. both walk records the
		// aborted epoch may have overwritten.
		for k := 0; k < at; k++ {
			labels, vals := epochLabels(k, *batch)
			m := merkle.NewCut(dig)
			if err := load(s, m, labels); err != nil {
				fmt.Printf("FAIL: epoch %d labels: %v\n", k, err)
				os.Exit(1)
			}
			for i, l := range labels {
				inMap, val, proof, e := m.Prove(l)
				if e || !inMap || !bytes.Equal(val, vals[i]) {
					fmt.Printf("FAIL: epoch %d label %x does not prove\n", k, l[:4])
					os.Exit(1)
				}
				h, e := merkle.VerifyMemb(l, val, proof)
				if e || !bytes.Equal(h, dig) {
					fmt.Printf("FAIL: epoch %d label %x proves to the wrong digest\n", k, l[:4])
					os.Exit(1)
				}
			}
		}
		if at < *nEpoch {
			labels, _ := epochLabels(at, *batch)
			m := merkle.NewCut(dig)
			if err := load(s, m, labels[:200]); err != nil {
				fmt.Printf("FAIL: uncommitted labels: %v\n", err)
				os.Exit(1)
			}
			for _, l := range labels[:200] {
				inMap, _, proof, e := m.Prove(l)
				if e || inMap {
					fmt.Printf("FAIL: uncommitted label %x is present\n", l[:4])
					os.Exit(1)
				}
				h, e := merkle.VerifyNonMemb(l, proof)
				if e || !bytes.Equal(h, dig) {
					fmt.Printf("FAIL: uncommitted label %x proves to the wrong digest\n", l[:4])
					os.Exit(1)
				}
			}
		}
		fmt.Printf("OK: store is consistent with epoch %d (%d probes)\n", at, s.probes)
		db.Close()
	}
}
