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
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/sanjit-bhat/pav/merkle"
)

var (
	dir      = flag.String("dir", "/var/tmp/diskbench", "where the LSM lives; must not be tmpfs")
	nSeed    = flag.Int("seed", 20_000_000, "leaves to seed")
	seedStep = flag.Int("seedstep", 500_000, "leaves per seeding batch")
	nBatch   = flag.Int("batch", 46_000, "insertions per measured epoch")
	nEpochs  = flag.Int("epochs", 2, "epochs to measure")
	nLookups = flag.Int("lookups", 2000, "lookups to measure")
	cacheMB  = flag.Int("cache", 64, "pebble block cache, MB")
	sweep    = flag.String("sweep", "", "comma-separated block cache sizes in MB to re-measure lookups at, reopening the LSM each time")
	warmD    = flag.Int("warm", -1, "keep the tree above this depth resident (-1 to disable)")
	keep     = flag.Bool("keep", false, "keep the LSM directory afterwards")
	reuse    = flag.Bool("reuse", false, "reuse an existing LSM directory and its digest")
	lenMajor = flag.Bool("lenmajor", false, "store keys length-major ([depth][label]) as AKD does, instead of value-major ([label][depth]). same tree, same probes, only locality differs")
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

// put writes without an fsync. node records do not need one: nothing reads
// them until HEAD names the digest they add up to, so a crash before putHead
// leaves records no reader can reach.
func (s *store) put(keys, vals [][]byte) {
	s.commit(keys, vals, pebble.NoSync)
}

// putHead is the epoch's one durable write, and its one fsync -- O(1) in the
// batch, however many records the epoch touched.
func (s *store) putHead(dig []byte) {
	s.commit([][]byte{headKey}, [][]byte{dig}, pebble.Sync)
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
		if !*keep {
			os.RemoveAll(*dir)
		}
	}()
	s := &store{db: db}

	var seed [32]byte
	rnd := rand.NewChaCha8(seed)
	dig := (&merkle.Map{}).Hash()
	maxDWrite := probeBound(*nSeed, 2)
	maxDRead := probeBound(*nSeed, 3)

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
		s.put(wk, wr)
		dig = oc.Hash()
		t3 := time.Now()
		s.putHead(dig)
		t4 := time.Now()
		tSync += t4.Sub(t3)

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

	// lookups, from a cold page cache so the reads reach the device.
	if err := db.Flush(); err != nil {
		panic(err)
	}
	dropCaches()
	base = s.counters
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
	report(s, base, ds, *cacheMB)

	for _, mb := range parseSweep(*sweep) {
		db.Close()
		db, err = pebble.Open(*dir, &pebble.Options{Cache: pebble.NewCache(int64(mb) << 20)})
		if err != nil {
			panic(err)
		}
		s.db = db
		dropCaches()
		base = s.counters
		ds = ds[:0]
		for i := 0; i < *nLookups; i++ {
			l := sample[rand.IntN(len(sample))]
			t := time.Now()
			m := merkle.NewCut(dig)
			loadBatch(s, m, [][]byte{l}, maxDRead)
			inMap, _, _, err := m.Prove(l)
			if err || !inMap {
				panic("lookup")
			}
			ds = append(ds, time.Since(t))
		}
		report(s, base, ds, mb)
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
