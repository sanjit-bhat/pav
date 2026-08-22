// diskbench runs the design-A merkle map against an on-disk LSM (Pebble),
// which is what §5.1 of the design note means by "embedded LSM, sorted,
// block-cached" and the substrate it predicts design A wins on.
//
// the point is what a lookup and an epoch cost when the tree does not fit in
// memory: how many disk reads the design asks for, and what they cost at a
// given cache size. the block cache is a flag so the same tree can be measured
// from fully cached to fully cold.
package main

import (
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/sanjit-bhat/pav/merkle"
)

var (
	dir        = flag.String("dir", "/var/tmp/diskbench", "where the LSM lives; must not be tmpfs")
	nSeed      = flag.Int("seed", 20_000_000, "leaves to seed")
	seedStep   = flag.Int("seedstep", 500_000, "leaves per seeding batch")
	nBatch     = flag.Int("batch", 46_000, "insertions per measured epoch")
	nEpochs    = flag.Int("epochs", 2, "epochs to measure")
	nLookups   = flag.Int("lookups", 2000, "lookups to measure")
	cacheMB    = flag.Int("cache", 64, "pebble block cache, MB")
	sweep      = flag.String("sweep", "", "comma-separated block cache sizes in MB to re-measure lookups at, reopening the LSM each time")
	warmD      = flag.Int("warm", -1, "keep the tree above this depth resident (-1 to disable)")
	keep       = flag.Bool("keep", false, "keep the LSM directory afterwards")
	reuse      = flag.Bool("reuse", false, "reuse an existing LSM: read HEAD and the saved sample labels, skip seeding and epochs, measure lookups only. run it under a memory cgroup to make reads reach the device")
	commitMode = flag.String("commit", "atomic", "epoch commit shape: \"atomic\" (records and HEAD in one batch) or \"headlast\" (records, then HEAD, which needs MVCC to be safe)")
	crashAt    = flag.String("crashat", "", "SIGKILL the process at a point in the epoch: \"mid\" (records written, HEAD not) or \"after\" (HEAD written)")
	lenMajor   = flag.Bool("lenmajor", false, "store keys length-major ([depth][label]) as AKD does, instead of value-major ([label][depth]). same tree, same probes, only locality differs")
)

// storeKey is the key the LSM actually sees. value-major is what merkle emits;
// length-major moves the depth to the front, which is how AKD serializes a
// NodeLabel and scatters one path's nodes across the keyspace by depth.
func storeKey(k []byte) []byte {
	if !*lenMajor {
		return k
	}
	n := len(k)
	out := make([]byte, 0, n)
	out = append(out, k[n-2:]...)
	return append(out, k[:n-2]...)
}

type counters struct {
	probes int
	hits   int
	rbytes int
	writes int
	wbytes int
}

type store struct {
	db *pebble.DB
	counters
}

func (s *store) get(keys [][]byte) [][]byte {
	out := make([][]byte, len(keys))
	for i, k := range keys {
		s.probes++
		v, closer, err := s.db.Get(storeKey(k))
		if err == pebble.ErrNotFound {
			continue
		}
		if err != nil {
			panic(err)
		}
		out[i] = append([]byte(nil), v...)
		s.hits++
		s.rbytes += len(v)
		closer.Close()
	}
	return out
}

// put writes node records without an fsync.
func (s *store) put(keys, vals [][]byte) {
	s.commit(keys, vals, pebble.NoSync)
}

// putHead is the epoch's one durable write, and its one fsync.
func (s *store) putHead(dig []byte) {
	s.commit([][]byte{headKey}, [][]byte{dig}, pebble.Sync)
}

// commitEpoch publishes an epoch. which shape is correct depends on whether
// the store keeps old versions.
//
// "headlast" writes the node records, then HEAD, and is what the design note's
// §2.3 and this log's §5 argue for. it is sound *under MVCC*, where a reader
// pinned at the old timestamp still sees the versions that epoch replaced. it
// is NOT sound on a single-version store: design A's node keys are mutable, so
// writing epoch e+1's records overwrites the ones HEAD still points through,
// and a crash before the HEAD write leaves the surviving digest unreachable.
//
// "atomic" puts the records and HEAD in one batch. a local engine gives that
// for free -- one Pebble batch is all-or-nothing and one fsync -- so the atomic
// step is O(B) but costs no more than HEAD alone did.
func (s *store) commitEpoch(keys, vals [][]byte, dig []byte) {
	if *commitMode == "headlast" {
		s.put(keys, vals)
		s.putHead(dig)
		return
	}
	s.commit(append(keys, headKey), append(vals, dig), pebble.Sync)
}

func (s *store) commit(keys, vals [][]byte, opts *pebble.WriteOptions) {
	b := s.db.NewBatch()
	for i, k := range keys {
		if err := b.Set(storeKey(k), vals[i], nil); err != nil {
			panic(err)
		}
		s.wbytes += len(k) + len(vals[i])
		s.writes++
	}
	if err := b.Commit(opts); err != nil {
		panic(err)
	}
}

func probeBound(n int, slack uint64) uint64 {
	var d uint64
	for 1<<d < uint64(n) {
		d++
	}
	return d + slack
}

// loadBatch loads every label's path with one deduped batch read.
func loadBatch(s *store, m *merkle.Map, labels [][]byte, maxD uint64) {
	seen := make(map[string]int, len(labels)*int(maxD))
	var keys [][]byte
	pks := make([][][]byte, len(labels))
	minDs := make([]uint64, len(labels))
	for i, l := range labels {
		minD, pk, needed := m.PathNeeds(l, maxD)
		if !needed {
			continue
		}
		minDs[i], pks[i] = minD, pk
		for _, k := range pk {
			if _, ok := seen[string(k)]; !ok {
				seen[string(k)] = len(keys)
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
			recs[j] = got[seen[string(k)]]
		}
		complete, err := m.LoadPath(l, minDs[i], recs)
		if err {
			panic("load")
		}
		if !complete {
			deep = append(deep, l)
		}
	}
	if len(deep) > 0 {
		loadBatch(s, m, deep, min(maxD+16, 256))
	}
}

func mkLabels(rnd *rand.ChaCha8, n int) (labels, vals [][]byte) {
	labels = make([][]byte, 0, n)
	vals = make([][]byte, 0, n)
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

var headKey = append(make([]byte, merkle.StoreKeyLen-1), 0xff)

// dropCaches empties the OS page cache, so a measured read really goes to the
// device rather than to the kernel's copy of it.
func dropCaches() {
	c := exec.Command("sh", "-c", "sync; echo agents | sudo -S sh -c 'echo 3 > /proc/sys/vm/drop_caches'")
	if err := c.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "could not drop caches (%v); reads may be served from the page cache\n", err)
	}
}

func main() {
	flag.Parse()
	if !*reuse {
		os.RemoveAll(*dir)
	}
	opts := &pebble.Options{Cache: pebble.NewCache(int64(*cacheMB) << 20)}
	db, err := pebble.Open(*dir, opts)
	if err != nil {
		panic(err)
	}
	defer func() {
		db.Close()
		// -reuse implies keep: it is a second pass over a tree someone else
		// seeded, and deleting it would strand the next pass.
		if !*keep && !*reuse {
			os.RemoveAll(*dir)
		}
	}()
	s := &store{db: db}

	var seed [32]byte
	rnd := rand.NewChaCha8(seed)
	dig := (&merkle.Map{}).Hash()
	maxDWrite := probeBound(*nSeed, 2)
	maxDRead := probeBound(*nSeed, 3)
	samplePath := *dir + ".sample"

	if *reuse {
		v, closer, err := db.Get(storeKey(headKey))
		if err != nil {
			panic(err)
		}
		dig = append([]byte(nil), v...)
		closer.Close()
		raw, err := os.ReadFile(samplePath)
		if err != nil {
			panic(err)
		}
		var sample [][]byte
		for i := 0; i+32 <= len(raw); i += 32 {
			sample = append(sample, raw[i:i+32])
		}
		lookups(s, dig, sample, maxDRead, nil)
		return
	}

	// seed entirely out of core, in batches, which is what a writer does.
	t0 := time.Now()
	var sample [][]byte
	for done := 0; done < *nSeed; done += *seedStep {
		n := min(*seedStep, *nSeed-done)
		labels, vals := mkLabels(rnd, n)
		sample = append(sample, labels[0])
		oc := merkle.NewCut(dig)
		loadBatch(s, oc, labels, maxDWrite)
		if _, err := oc.Update(labels, vals); err {
			panic("seed update")
		}
		s.put(oc.Records())
		dig = oc.Hash()
		if (done/(*seedStep))%20 == 0 {
			fmt.Fprintf(os.Stderr, "seeded %d/%d in %v\n", done+n, *nSeed, time.Since(t0))
		}
	}
	s.putHead(dig)
	if err := db.Flush(); err != nil {
		panic(err)
	}
	var flat []byte
	for _, l := range sample {
		flat = append(flat, l...)
	}
	if err := os.WriteFile(samplePath, flat, 0o644); err != nil {
		panic(err)
	}
	seedWrites, seedBytes := s.writes, s.wbytes
	fmt.Printf("seed:   %d leaves, %d records written, %.1f GB written, %v\n",
		*nSeed, seedWrites, float64(seedBytes)/1e9, time.Since(t0))
	if du, err := exec.Command("du", "-sb", *dir).Output(); err == nil {
		fmt.Printf("        on disk: %s", du)
	}

	// measured epochs.
	base := s.counters
	var tLoad, tUpd, tWrite, tSync time.Duration
	var tapeBytes int
	var warm *merkle.Map
	for e := 0; e < *nEpochs; e++ {
		labels, vals := mkLabels(rnd, *nBatch)
		digPrev := dig
		oc := merkle.NewCut(dig)

		t0 := time.Now()
		loadBatch(s, oc, labels, maxDWrite)
		t1 := time.Now()
		tape, err := oc.Update(labels, vals)
		if err {
			panic("update")
		}
		wk, wr := oc.Records()
		t2 := time.Now()
		dig = oc.Hash()
		if *crashAt == "mid" {
			// only the records, then die: the case HEAD-last has to survive.
			s.put(wk, wr)
			fmt.Println("CRASH mid-epoch, records written, HEAD not")
			os.Stdout.Sync()
			syscall.Kill(syscall.Getpid(), syscall.SIGKILL)
		}
		t3 := time.Now()
		s.commitEpoch(wk, wr, dig)
		t4 := time.Now()
		tSync += t4.Sub(t3) - (t3.Sub(t2) - t3.Sub(t2))
		if *crashAt == "after" {
			fmt.Printf("CRASH after commit, digest %x\n", dig)
			os.Stdout.Sync()
			syscall.Kill(syscall.Getpid(), syscall.SIGKILL)
		}

		tapeBytes += len(tape)
		tLoad += t1.Sub(t0)
		tUpd += t2.Sub(t1)
		tWrite += t3.Sub(t2)
		if *warmD >= 0 {
			w, hOld, err := merkle.ApplyUpdate(labels, vals, tape)
			if err || string(hOld) != string(digPrev) {
				panic("apply tape")
			}
			w.Evict(uint64(*warmD))
			warm = w
		}
	}
	n := float64(*nBatch * *nEpochs)
	fmt.Printf("epoch:  %.1f us/insert (load %.1f, upd %.1f, write %.1f)  %.2f probes  %.2f hits  %.2f writes  %.0f B tape  |  %.2f s/epoch, HEAD fsync %.2f ms/epoch\n",
		float64((tLoad+tUpd+tWrite).Microseconds())/n,
		float64(tLoad.Microseconds())/n,
		float64(tUpd.Microseconds())/n,
		float64(tWrite.Microseconds())/n,
		float64(s.probes-base.probes)/n,
		float64(s.hits-base.hits)/n,
		float64(s.writes-base.writes)/n,
		float64(tapeBytes)/n,
		float64((tLoad+tUpd+tWrite).Seconds())/float64(*nEpochs),
		float64(tSync.Microseconds())/1e3/float64(*nEpochs))

	lookups(s, dig, sample, maxDRead, warm)
}

// lookups measures one path load plus a proof, from a cold page cache, at each
// requested block cache size.
func lookups(s *store, dig []byte, sample [][]byte, maxDRead uint64, warm *merkle.Map) {
	if err := s.db.Flush(); err != nil {
		panic(err)
	}
	sizes := append([]int{*cacheMB}, parseSweep(*sweep)...)
	for n, mb := range sizes {
		if n > 0 {
			s.db.Close()
			db, err := pebble.Open(*dir, &pebble.Options{Cache: pebble.NewCache(int64(mb) << 20)})
			if err != nil {
				panic(err)
			}
			s.db = db
		}
		dropCaches()
		base := s.counters
		ds := make([]time.Duration, 0, *nLookups)
		for i := 0; i < *nLookups; i++ {
			l := sample[rand.IntN(len(sample))]
			t := time.Now()
			m := warm
			if m == nil {
				m = merkle.NewCut(dig)
			}
			loadBatch(s, m, [][]byte{l}, maxDRead)
			inMap, _, _, err := m.Prove(l)
			if err || !inMap {
				panic("lookup")
			}
			ds = append(ds, time.Since(t))
			if warm != nil {
				warm.EvictPath(l, uint64(*warmD))
			}
		}
		report(s, base, ds, mb)
	}
	probeShapes(s, sample, maxDRead)
}

// akdKeys is AKD's probe set for a path: at every level it fetches the node
// *and* its sibling, because a TreeNode record names its children but does not
// carry their hashes. both are prefixes of the label with at most the last bit
// flipped, so they are nameable in our own store, and this measures AKD's
// access pattern against the same tree and the same engine.
func akdKeys(label []byte, maxD uint64) (keys [][]byte) {
	flip := make([]byte, len(label))
	for d := uint64(0); d <= maxD; d++ {
		keys = append(keys, merkle.StoreKey(label, d))
		if d == 0 {
			continue
		}
		copy(flip, label)
		flip[(d-1)/8] ^= 1 << ((d - 1) % 8)
		keys = append(keys, merkle.StoreKey(flip, d))
	}
	return
}

// probeShapes times the storage work alone for the two access patterns, so the
// comparison is probe set against probe set with everything else held fixed.
func probeShapes(s *store, sample [][]byte, maxD uint64) {
	for _, shape := range []string{"pav (one probe per level)", "AKD (node and sibling per level)"} {
		dropCaches()
		base := s.counters
		ds := make([]time.Duration, 0, *nLookups)
		for i := 0; i < *nLookups; i++ {
			l := sample[rand.IntN(len(sample))]
			var keys [][]byte
			if shape[0] == 'p' {
				keys = merkle.PathKeys(l, 0, maxD)
			} else {
				keys = akdKeys(l, maxD)
			}
			t := time.Now()
			s.get(keys)
			ds = append(ds, time.Since(t))
		}
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		var sum time.Duration
		for _, d := range ds {
			sum += d
		}
		fmt.Printf("probes: %-34s mean %6.0f us  p50 %6.0f us  p99 %7.0f us  %.1f probes  %.1f hits\n",
			shape,
			float64(sum.Microseconds())/float64(len(ds)),
			float64(ds[len(ds)/2].Microseconds()),
			float64(ds[len(ds)*99/100].Microseconds()),
			float64(s.probes-base.probes)/float64(*nLookups),
			float64(s.hits-base.hits)/float64(*nLookups))
	}
}

func parseSweep(spec string) (out []int) {
	if spec == "" {
		return nil
	}
	for _, f := range strings.Split(spec, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return
}

func report(s *store, base counters, ds []time.Duration, cacheMB int) {
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	var sum time.Duration
	for _, d := range ds {
		sum += d
	}
	fmt.Printf("lookup: mean %6.0f us  p50 %6.0f us  p99 %7.0f us  %.2f probes  %.2f hits  %.0f B read  (cache %d MB)\n",
		float64(sum.Microseconds())/float64(len(ds)),
		float64(ds[len(ds)/2].Microseconds()),
		float64(ds[len(ds)*99/100].Microseconds()),
		float64(s.probes-base.probes)/float64(*nLookups),
		float64(s.hits-base.hits)/float64(*nLookups),
		float64(s.rbytes-base.rbytes)/float64(*nLookups),
		cacheMB)
}
