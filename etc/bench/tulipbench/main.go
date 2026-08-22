// tulipbench answers §8's first question: what a merkle path probe costs on
// Tulip. it runs a whole Tulip deployment in one process, so the numbers are
// protocol cost with a loopback network, i.e. a floor.
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
	"github.com/mit-pdos/tulip/replica"
	"github.com/mit-pdos/tulip/tulip"
	"github.com/mit-pdos/tulip/txn"
)

var (
	nGroups  = flag.Int("groups", 1, "replica groups")
	nReplica = flag.Int("replicas", 3, "replicas per group")
	nKeys    = flag.Int("keys", 100_000, "keys to preload")
	nProbes  = flag.Int("probes", 64, "keys in one path probe")
	nIters   = flag.Int("iters", 200, "measured iterations")
	writeSz  = flag.Int("writesz", 0, "keys per write txn (0 to skip)")
)

func addrMaps(base int) (map[uint64]map[uint64]grove_ffi.Address, map[uint64]map[uint64]uint64) {
	gaddrm := make(map[uint64]map[uint64]grove_ffi.Address)
	px := make(map[uint64]map[uint64]uint64)
	for g := 0; g < *nGroups; g++ {
		am := make(map[uint64]grove_ffi.Address)
		pm := make(map[uint64]uint64)
		for r := 0; r < *nReplica; r++ {
			am[uint64(r)] = grove_ffi.MakeAddress(fmt.Sprintf("127.0.0.1:%d", base+g*100+r*10))
			pm[uint64(r)] = grove_ffi.MakeAddress(fmt.Sprintf("127.0.0.1:%d", base+5000+g*100+r*10))
		}
		gaddrm[uint64(g)] = am
		px[uint64(g)] = pm
	}
	return gaddrm, px
}

func main() {
	flag.Parse()
	dir, err := os.MkdirTemp("", "tulipbench")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chdir(dir); err != nil {
		panic(err)
	}
	// gokv's FileAppend writes under durable/.
	if err := os.Mkdir("durable", 0o755); err != nil {
		panic(err)
	}

	gaddrm, px := addrMaps(49000)
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
	// paxos needs a leader before anything commits.
	time.Sleep(3 * time.Second)

	// a merkle node key is 33 B: the label prefix plus its length.
	mkKey := func(i int) string {
		b := make([]byte, 33)
		rnd := rand.New(rand.NewPCG(uint64(i), 0xf00d))
		for j := range b {
			b[j] = byte(rnd.Uint32())
		}
		return string(b)
	}
	// a node record is ~65 B.
	val := string(make([]byte, 65))

	// preload.
	load := txn.MkTxn(0, gaddrm)
	t0 := time.Now()
	const perTxn = 100
	for i := 0; i < *nKeys; i += perTxn {
		lo := i
		ok := load.Run(func(t *txn.Txn) bool {
			for j := lo; j < lo+perTxn && j < *nKeys; j++ {
				t.Write(mkKey(j), val)
			}
			return true
		})
		if !ok {
			panic("preload aborted")
		}
	}
	fmt.Fprintf(os.Stderr, "preloaded %d keys in %v\n", *nKeys, time.Since(t0))
	// let preload commits land before reading.
	time.Sleep(3 * time.Second)

	report := func(name string, ds []time.Duration, per int) {
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		var sum time.Duration
		for _, d := range ds {
			sum += d
		}
		mean := sum / time.Duration(len(ds))
		fmt.Printf("%-28s n=%-5d mean %8.1f us  p50 %8.1f us  p99 %8.1f us  per-key %6.1f us\n",
			name, len(ds),
			float64(mean.Nanoseconds())/1e3,
			float64(ds[len(ds)/2].Nanoseconds())/1e3,
			float64(ds[len(ds)*99/100].Nanoseconds())/1e3,
			float64(mean.Nanoseconds())/1e3/float64(per))
	}

	// 1. one key, one read-only txn.
	single := txn.MkTxn(1, gaddrm)
	ds := make([]time.Duration, 0, *nIters)
	for i := 0; i < *nIters; i++ {
		k := mkKey(rand.IntN(*nKeys))
		t := time.Now()
		single.Run(func(tx *txn.Txn) bool {
			tx.Read(k)
			return true
		})
		ds = append(ds, time.Since(t))
	}
	report("read 1 key, 1 txn", ds, 1)

	// 2. a whole path in one txn: nProbes sequential reads.
	ds = ds[:0]
	for i := 0; i < *nIters; i++ {
		base := rand.IntN(*nKeys)
		t := time.Now()
		single.Run(func(tx *txn.Txn) bool {
			for j := 0; j < *nProbes; j++ {
				tx.Read(mkKey((base + j) % *nKeys))
			}
			return true
		})
		ds = append(ds, time.Since(t))
	}
	report("path, 1 txn sequential", ds, *nProbes)

	// 3. a whole path as nProbes concurrent single-key read-only txns.
	pool := make([]*txn.Txn, *nProbes)
	for i := range pool {
		pool[i] = txn.MkTxn(uint64(10+i), gaddrm)
	}
	ds = ds[:0]
	for i := 0; i < *nIters; i++ {
		base := rand.IntN(*nKeys)
		t := time.Now()
		var wg sync.WaitGroup
		for j := 0; j < *nProbes; j++ {
			wg.Add(1)
			go func(j int) {
				defer wg.Done()
				k := mkKey((base + j) % *nKeys)
				pool[j].Run(func(tx *txn.Txn) bool {
					tx.Read(k)
					return true
				})
			}(j)
		}
		wg.Wait()
		ds = append(ds, time.Since(t))
	}
	report("path, concurrent txns", ds, *nProbes)

	// 4. sustained read throughput: nProbes client goroutines, own txn each.
	{
		var wg sync.WaitGroup
		var mu sync.Mutex
		var count int
		stop := time.Now().Add(5 * time.Second)
		for j := 0; j < *nProbes; j++ {
			wg.Add(1)
			go func(j int) {
				defer wg.Done()
				n := 0
				for time.Now().Before(stop) {
					k := mkKey(rand.IntN(*nKeys))
					pool[j].Run(func(tx *txn.Txn) bool {
						tx.Read(k)
						return true
					})
					n++
				}
				mu.Lock()
				count += n
				mu.Unlock()
			}(j)
		}
		wg.Wait()
		fmt.Printf("%-28s %d clients, %.0f reads/s\n", "read throughput", *nProbes, float64(count)/5)
	}

	if *writeSz > 0 {
		ds = ds[:0]
		for i := 0; i < *nIters; i++ {
			base := rand.IntN(*nKeys)
			t := time.Now()
			single.Run(func(tx *txn.Txn) bool {
				for j := 0; j < *writeSz; j++ {
					tx.Write(mkKey((base+j)%*nKeys), val)
				}
				return true
			})
			ds = append(ds, time.Since(t))
		}
		report(fmt.Sprintf("write %d keys, 1 txn", *writeSz), ds, *writeSz)
	}
}
