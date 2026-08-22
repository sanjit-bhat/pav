// ktbench runs the design-A merkle map against a real Tulip deployment: the
// whole deployment in one process, so the numbers are protocol floors.
//
// an epoch is one deduped batch read of computable prefix keys, one in-memory
// batch update that also emits the audit tape, and one write of the records
// the update changed. a lookup is one batch read of one path's prefix keys.
package main

import (
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/tulip/gcoord"
	"github.com/mit-pdos/tulip/params"
	"github.com/mit-pdos/tulip/replica"
	"github.com/mit-pdos/tulip/trusted_time"
	"github.com/mit-pdos/tulip/tulip"
	"github.com/mit-pdos/tulip/txn"
	"github.com/sanjit-bhat/pav/merkle"
)

var (
	nGroups   = flag.Int("groups", 1, "replica groups")
	nReplica  = flag.Int("replicas", 3, "replicas per group")
	nSeed     = flag.Int("seed", 200_000, "leaves to seed")
	nBatch    = flag.Int("batch", 10_000, "insertions per epoch")
	nEpochs   = flag.Int("epochs", 3, "epochs to measure")
	nLookups  = flag.Int("lookups", 2000, "lookups to measure")
	nWorkers  = flag.Int("workers", 64, "concurrent readers for a batch read")
	writeChnk = flag.Int("writechunk", 1000, "keys per write txn")
	snapRead  = flag.Bool("snap", true, "read a batch at one timestamp via the group coordinators, rather than one read-only txn per key")
	warmD     = flag.Int("warm", -1, "keep the tree above this depth resident, warmed from each epoch's tape (-1 to disable)")
)

// snapshot reads a whole batch of keys at one timestamp, which is what design
// A's consistency argument wants and what Tulip's Txn cannot express: Read is
// one round trip per key and a Txn is not concurrency-safe. going at the group
// coordinators directly is a read-only transaction at ts with no prepare or
// commit, so it is both cheaper and more correct than a txn per key.
// one coordinator per group would serialize the batch on that coordinator's
// lock and condvar, so there is a pool of them, all attached to the same ts.
type snapshot struct {
	pool    []map[uint64]*gcoord.GroupCoordinator
	ngroups uint64
}

func newSnapshot(gaddrm map[uint64]map[uint64]grove_ffi.Address, n int) *snapshot {
	s := &snapshot{ngroups: uint64(len(gaddrm))}
	for i := 0; i < n; i++ {
		gcs := make(map[uint64]*gcoord.GroupCoordinator)
		for gid, addrm := range gaddrm {
			gcs[gid] = gcoord.Start(addrm)
		}
		s.pool = append(s.pool, gcs)
	}
	return s
}

func (s *snapshot) group(key string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(key); i++ {
		h ^= uint64(key[i])
		h *= 1099511628211
	}
	return h % s.ngroups
}

// readSid is a timestamp site reserved for snapshot reads, so a read never
// picks the same timestamp as a writer and abort it.
const readSid = 1023

func (s *snapshot) begin() uint64 {
	ts := trusted_time.GetTime()
	n := params.N_TXN_SITES
	tid := (ts+n)/n*n + readSid
	for trusted_time.GetTime() <= tid {
	}
	return s.at(tid)
}

// at pins the read to a timestamp someone else chose, which is what reading an
// epoch requires: HEAD names the timestamp its node writes had all committed
// by, and the nodes must be read there rather than at "now". reading at "now"
// is wrong precisely in the case MVCC was supposed to cover -- a writer that
// died after its node writes and before HEAD leaves newer versions of records
// the surviving HEAD still points through.
func (s *snapshot) at(tid uint64) uint64 {
	for _, gcs := range s.pool {
		for _, gc := range gcs {
			gc.Attach(tid)
		}
	}
	return tid
}

// store is a Tulip-backed KV. reads fan out over a pool of read-only txns
// because Tulip has no batched read primitive and a Txn is not
// concurrency-safe; writes go in chunked write txns.
type store struct {
	snap   *snapshot
	pool   []*txn.Txn
	probes int
	hits   int
	rbytes int
	wbytes int
	writes int
	aborts int
}

// headKey holds the published epoch: its number and its digest. it is written
// last, and read in the same snapshot as the nodes.
//
// that is the whole of R2 and R3 under MVCC. the node writes for an epoch may
// land in any order, in as many transactions as convenient, because nothing
// reads them until HEAD names the digest they add up to, and a reader that
// took HEAD at ts sees exactly the versions that were committed by ts. a crash
// before the HEAD write leaves records no reader can reach. so the atomic step
// is one key, O(1) in the batch, with no transaction over the batch and no
// write-ordering discipline beyond "HEAD last".
var headKey = append(make([]byte, merkle.StoreKeyLen-1), 0xff)

func (s *store) get(keys [][]byte) [][]byte {
	if *snapRead {
		return s.getSnap(keys, 0)
	}
	return s.getTxn(keys)
}

// getAt reads at the epoch's own timestamp.
func (s *store) getAt(keys [][]byte, ts uint64) [][]byte {
	if *snapRead {
		return s.getSnap(keys, ts)
	}
	return s.getTxn(keys)
}

func (s *store) getSnap(keys [][]byte, ts uint64) [][]byte {
	out := make([][]byte, len(keys))
	if ts == 0 {
		ts = s.snap.begin()
	} else {
		s.snap.at(ts)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	n := *nWorkers
	for w := 0; w < n; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			var probes, hits, rbytes int
			for i := w; i < len(keys); i += n {
				k := string(keys[i])
				probes++
				v, ok := s.snap.pool[w][s.snap.group(k)].Read(ts, k)
				if ok && v.Present {
					out[i] = []byte(v.Content)
					hits++
					rbytes += len(v.Content)
				}
			}
			mu.Lock()
			s.probes += probes
			s.hits += hits
			s.rbytes += rbytes
			mu.Unlock()
		}(w)
	}
	wg.Wait()
	return out
}

func (s *store) getTxn(keys [][]byte) [][]byte {
	out := make([][]byte, len(keys))
	var wg sync.WaitGroup
	var mu sync.Mutex
	n := len(s.pool)
	for w := 0; w < n; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			var probes, hits, rbytes int
			for i := w; i < len(keys); i += n {
				k := string(keys[i])
				probes++
				s.pool[w].Run(func(tx *txn.Txn) bool {
					v, ok := tx.Read(k)
					if ok && v.Present {
						out[i] = []byte(v.Content)
						hits++
						rbytes += len(v.Content)
					}
					return true
				})
			}
			mu.Lock()
			s.probes += probes
			s.hits += hits
			s.rbytes += rbytes
			mu.Unlock()
		}(w)
	}
	wg.Wait()
	return out
}

// putHead publishes an epoch: the digest, plus the timestamp its node writes
// had all committed by. a reader must read the nodes *at that timestamp*, not
// at "now" -- that is what makes HEAD-last sound here and unsound on a
// single-version store. a writer that died after its node writes and before
// HEAD leaves newer versions of records the surviving HEAD points through;
// reading at the surviving HEAD's timestamp does not see them.
func (s *store) putHead(dig []byte) {
	ts := trusted_time.GetTime()
	v := make([]byte, 0, len(dig)+8)
	v = append(v, dig...)
	for i := 0; i < 8; i++ {
		v = append(v, byte(ts>>(8*i)))
	}
	s.put([][]byte{headKey}, [][]byte{v})
}

// readHead returns the published digest and the timestamp to read nodes at.
func (s *store) readHead() ([]byte, uint64) {
	v := s.get([][]byte{headKey})[0]
	if len(v) != 40 {
		panic("HEAD")
	}
	var ts uint64
	for i := 7; i >= 0; i-- {
		ts = ts<<8 | uint64(v[32+i])
	}
	return v[:32], ts
}

func (s *store) put(keys, vals [][]byte) {
	for lo := 0; lo < len(keys); lo += *writeChnk {
		hi := min(lo+*writeChnk, len(keys))
		// Tulip aborts a write txn occasionally even with one writer and no
		// concurrent readers -- about 1 in 7,000 observed. a real writer
		// retries, so do that, and count it.
		var ok bool
		for try := 0; try < 10 && !ok; try++ {
			if try > 0 {
				s.aborts++
			}
			ok = s.pool[0].Run(func(tx *txn.Txn) bool {
				for i := lo; i < hi; i++ {
					tx.Write(string(keys[i]), string(vals[i]))
				}
				return true
			})
		}
		if !ok {
			panic("write txn aborted ten times")
		}
		for i := lo; i < hi; i++ {
			s.wbytes += len(keys[i]) + len(vals[i])
			s.writes++
		}
	}
}

func probeBound(n int, slack uint64) uint64 {
	var d uint64
	for 1<<d < uint64(n) {
		d++
	}
	// leaf depth is log2(N) + Geom(1/2); the tail costs a second read.
	return d + slack
}

// loadBatch loads every label's path into m with one deduped batch read,
// then a second, small read for the paths that outran the bound.
func loadBatch(s *store, m *merkle.Map, labels [][]byte, maxD uint64) {
	loadBatchAt(s, m, labels, maxD, 0)
}

func loadBatchAt(s *store, m *merkle.Map, labels [][]byte, maxD uint64, ts uint64) {
	seen := make(map[string]int, len(labels)*int(maxD))
	var keys [][]byte
	pks := make([][][]byte, len(labels))
	minDs := make([]uint64, len(labels))
	for i, l := range labels {
		// the map says which records it is missing, so a warm top is not
		// re-read.
		minD, pk, needed := m.PathNeeds(l, maxD)
		if !needed {
			continue
		}
		minDs[i] = minD
		pks[i] = pk
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
	got := s.getAt(keys, ts)

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
		loadBatchAt(s, m, deep, min(maxD+16, 256), ts)
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

func main() {
	flag.Parse()
	dir, err := os.MkdirTemp("", "ktbench")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chdir(dir); err != nil {
		panic(err)
	}
	if err := os.Mkdir("durable", 0o755); err != nil {
		panic(err)
	}

	gaddrm := make(map[uint64]map[uint64]grove_ffi.Address)
	px := make(map[uint64]map[uint64]uint64)
	for g := 0; g < *nGroups; g++ {
		am := make(map[uint64]grove_ffi.Address)
		pm := make(map[uint64]uint64)
		for r := 0; r < *nReplica; r++ {
			am[uint64(r)] = grove_ffi.MakeAddress(fmt.Sprintf("127.0.0.1:%d", 49000+g*100+r*10))
			pm[uint64(r)] = grove_ffi.MakeAddress(fmt.Sprintf("127.0.0.1:%d", 54000+g*100+r*10))
		}
		gaddrm[uint64(g)] = am
		px[uint64(g)] = pm
	}
	maps := make(tulip.AddressMaps)
	for g, am := range gaddrm {
		maps[g] = tulip.AddressMap(am)
	}
	for g, am := range gaddrm {
		for r := range am {
			replica.Start(g, r, am[r], fmt.Sprintf("wal-%d-%d", g, r),
				px[g], fmt.Sprintf("walpx-%d-%d", g, r), maps)
		}
	}
	time.Sleep(3 * time.Second)

	s := &store{snap: newSnapshot(gaddrm, *nWorkers)}
	for i := 0; i < *nWorkers; i++ {
		s.pool = append(s.pool, txn.MkTxn(uint64(i), gaddrm))
	}

	var seed [32]byte
	rnd := rand.NewChaCha8(seed)

	// seed: build in core, then spill. a real deployment bulk-loads.
	mem := &merkle.Map{}
	seedLabels, seedVals := mkLabels(rnd, *nSeed)
	if _, err := mem.Update(seedLabels, seedVals); err {
		panic("seed")
	}
	dig := mem.Hash()
	t0 := time.Now()
	sk, sr := mem.Records()
	s.put(sk, sr)
	s.putHead(dig)
	fmt.Fprintf(os.Stderr, "seeded %d leaves as %d records in %v\n", *nSeed, len(sk), time.Since(t0))
	mem = nil

	maxDWrite := probeBound(*nSeed, 2)
	maxDRead := probeBound(*nSeed, 3)

	// epochs.
	var tLoad, tUpd, tWrite time.Duration
	var tapeBytes int
	var warm *merkle.Map
	base := *s
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
		// HEAD last, and on its own, so it is the one atomic step -- see
		// putHead for why that needs the timestamp.
		dig = oc.Hash()
		s.putHead(dig)
		t3 := time.Now()

		tapeBytes += len(tape)
		if *warmD >= 0 {
			w, hOld, err := merkle.ApplyUpdate(labels, vals, tape)
			if err || string(hOld) != string(digPrev) {
				panic("apply tape")
			}
			w.Evict(uint64(*warmD))
			warm = w
		}
		tLoad += t1.Sub(t0)
		tUpd += t2.Sub(t1)
		tWrite += t3.Sub(t2)
	}
	n := float64(*nBatch * *nEpochs)
	fmt.Printf("epoch:  %.1f us/insert (load %.1f, upd %.1f, write %.1f)  %.2f probes  %.2f hits  %.2f writes  %.0f B tape  |  %.2f s/epoch\n",
		float64((tLoad+tUpd+tWrite).Microseconds())/n,
		float64(tLoad.Microseconds())/n,
		float64(tUpd.Microseconds())/n,
		float64(tWrite.Microseconds())/n,
		float64(s.probes-base.probes)/n,
		float64(s.hits-base.hits)/n,
		float64(s.writes-base.writes)/n,
		float64(tapeBytes)/n,
		float64((tLoad+tUpd+tWrite).Seconds())/float64(*nEpochs))

	// lookups, one path at a time, as a replica would serve them.
	base = *s
	ds := make([]time.Duration, 0, *nLookups)
	for i := 0; i < *nLookups; i++ {
		l := seedLabels[rand.IntN(len(seedLabels))]
		t := time.Now()
		// read HEAD, then read the nodes at the timestamp it names.
		head, headTs := s.readHead()
		m := warm
		if m == nil || string(head) != string(dig) {
			m = merkle.NewCut(head)
		}
		loadBatchAt(s, m, [][]byte{l}, maxDRead, headTs)
		inMap, _, _, err := m.Prove(l)
		if err || !inMap {
			panic("lookup")
		}
		if warm != nil {
			warm.EvictPath(l, uint64(*warmD))
		}
		ds = append(ds, time.Since(t))
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	var sum time.Duration
	for _, d := range ds {
		sum += d
	}
	fmt.Printf("write txn retries: %d over %d txns\n", s.aborts, s.writes / *writeChnk)
	fmt.Printf("lookup: mean %.0f us  p50 %.0f us  p99 %.0f us  %.2f probes  %.2f hits\n",
		float64(sum.Microseconds())/float64(len(ds)),
		float64(ds[len(ds)/2].Microseconds()),
		float64(ds[len(ds)*99/100].Microseconds()),
		float64(s.probes-base.probes)/float64(*nLookups),
		float64(s.hits-base.hits)/float64(*nLookups))
}
