package kt

import (
	"math/rand/v2"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/aclements/go-moremath/stats"
	"github.com/mit-pdos/pav/benchutil"
	"github.com/mit-pdos/pav/cryptoffi"
)

const (
	defNSeed int = 100_000
)

func TestBenchSeed(t *testing.T) {
	start := time.Now()
	seedServer(1_000_000)
	total := time.Since(start)
	t.Log(total)
}

func TestBenchPut(t *testing.T) {
	serv, rnd, vrfPk, _ := seedServer(defNSeed)
	nOps := 2_000

	start := time.Now()
	for i := 0; i < nOps; i++ {
		u := rnd.Uint64()
		dig, lat, bound, err := serv.Put(u, mkDefVal())
		if err {
			t.Fatal()
		}
		if checkMemb(vrfPk, u, 0, dig.Dig, lat) {
			t.Fatal()
		}
		if checkNonMemb(vrfPk, u, 1, dig.Dig, bound) {
			t.Fatal()
		}
	}
	total := time.Since(start)

	m0 := float64(total.Microseconds()) / float64(nOps)
	m1 := float64(total.Milliseconds())
	benchutil.Report(nOps, []*benchutil.Metric{
		{N: m0, Unit: "us/op"},
		{N: m1, Unit: "total(ms)"},
	})
}

func TestBenchPutBatch(t *testing.T) {
	serv, rnd, _, _ := seedServer(defNSeed)
	nOps := 100
	nInsert := 1_000

	start := time.Now()
	for i := 0; i < nOps; i++ {
		wg := new(sync.WaitGroup)
		wg.Add(nInsert)
		for j := 0; j < nInsert; j++ {
			u := rnd.Uint64()
			go func() {
				serv.Put(u, mkDefVal())
				wg.Done()
			}()
		}
		wg.Wait()
	}
	total := time.Since(start)

	m0 := float64(total.Microseconds()) / float64(nOps)
	m1 := float64(total.Milliseconds())
	benchutil.Report(nOps, []*benchutil.Metric{
		{N: m0, Unit: "us/op"},
		{N: m1, Unit: "total(ms)"},
	})
}

func TestBenchPutSize(t *testing.T) {
	serv, rnd, _, _ := seedServer(defNSeed)
	u := rnd.Uint64()
	dig, lat, bound, err := serv.Put(u, mkDefVal())
	if err {
		t.Fatal()
	}
	p := &ServerPutReply{Dig: dig, Latest: lat, Bound: bound, Err: err}
	pb := ServerPutReplyEncode(nil, p)
	benchutil.Report(1, []*benchutil.Metric{
		{N: float64(len(pb)), Unit: "B"},
	})
}

func TestBenchGet(t *testing.T) {
	serv, _, vrfPk, uids := seedServer(defNSeed)
	nOps := 3_000

	start := time.Now()
	for i := 0; i < nOps; i++ {
		u := uids[i]
		dig, hist, isReg, lat, bound := serv.Get(u)
		if !isReg {
			t.Fatal()
		}
		if checkHist(vrfPk, u, dig.Dig, hist) {
			t.Fatal()
		}
		if checkMemb(vrfPk, u, 0, dig.Dig, lat) {
			t.Fatal()
		}
		if checkNonMemb(vrfPk, u, 1, dig.Dig, bound) {
			t.Fatal()
		}
	}
	total := time.Since(start)

	m0 := float64(total.Microseconds()) / float64(nOps)
	m1 := float64(total.Milliseconds())
	benchutil.Report(nOps, []*benchutil.Metric{
		{N: m0, Unit: "us/op"},
		{N: m1, Unit: "total(ms)"},
	})
}

func TestBenchGetScale(t *testing.T) {
	nSeed := defNSeed
	serv, _, _, uids := seedServer(nSeed)
	maxNCli := 3 * runtime.NumCPU()
	cliLats := make([][]float64, maxNCli)
	cliMu := make([]sync.Mutex, maxNCli)
	prevTime := time.Now()
	sampleData := make([]float64, 0, 2_000_000)

	for i := 0; i < maxNCli; i++ {
		go func() {
			prev := time.Now()
			for {
				u := uids[rand.IntN(nSeed)]
				serv.Get(u)
				end := time.Now()
				diff := end.Sub(prev)
				prev = end

				cliMu[i].Lock()
				cliLats[i] = append(cliLats[i], float64(diff.Microseconds()))
				cliMu[i].Unlock()
			}
		}()
		time.Sleep(time.Second)

		// measure.
		sampleData = sampleData[:0]
		samp := stats.Sample{Xs: sampleData}
		for j := 0; j <= i; j++ {
			cliMu[j].Lock()
			lats := cliLats[j]
			cliLats[j] = nil
			cliMu[j].Unlock()

			samp.Xs = append(samp.Xs, lats...)
		}
		samp.Sort()

		ops := int(samp.Weight())
		now := time.Now()
		diffTime := now.Sub(prevTime)
		prevTime = now

		// report.
		tput := float64(ops) / diffTime.Seconds()
		benchutil.Report(ops, []*benchutil.Metric{
			{N: float64(i + 1), Unit: "nCli"},
			{N: tput, Unit: "op/s"},
			{N: samp.Mean(), Unit: "mean(us)"},
			{N: samp.StdDev(), Unit: "stddev"},
			{N: samp.Quantile(0.99), Unit: "p99"},
		})
	}
}

func TestBenchGetSize(t *testing.T) {
	serv, _, _, uids := seedServer(defNSeed)
	dig, hist, isReg, lat, bound := serv.Get(uids[0])
	if !isReg {
		t.Fatal()
	}
	p := &ServerGetReply{Dig: dig, Hist: hist, IsReg: isReg, Latest: lat, Bound: bound}
	pb := ServerGetReplyEncode(nil, p)
	benchutil.Report(1, []*benchutil.Metric{
		{N: float64(len(pb)), Unit: "B"},
	})
}

func TestBenchSelfMon(t *testing.T) {
	serv, _, vrfPk, uids := seedServer(defNSeed)
	nOps := 6_000

	start := time.Now()
	for i := 0; i < nOps; i++ {
		u := uids[i]
		dig, bound := serv.SelfMon(u)
		if checkNonMemb(vrfPk, u, 1, dig.Dig, bound) {
			t.Fatal()
		}
	}
	total := time.Since(start)

	m0 := float64(total.Microseconds()) / float64(nOps)
	m1 := float64(total.Milliseconds())
	benchutil.Report(nOps, []*benchutil.Metric{
		{N: m0, Unit: "us/op"},
		{N: m1, Unit: "total(ms)"},
	})
}

func TestBenchSelfMonSize(t *testing.T) {
	serv, _, _, uids := seedServer(defNSeed)
	dig, bound := serv.SelfMon(uids[0])
	p := &ServerSelfMonReply{Dig: dig, Bound: bound}
	pb := ServerSelfMonReplyEncode(nil, p)
	benchutil.Report(1, []*benchutil.Metric{
		{N: float64(len(pb)), Unit: "B"},
	})
}

func TestBenchAudit(t *testing.T) {
	serv, rnd, _, _ := seedServer(defNSeed)
	aud, _ := NewAuditor()
	epoch := updAuditor(t, serv, aud, 0)
	nOps := 100
	nInsert := 1_000

	start := time.Now()
	for i := 0; i < nOps; i++ {
		wg := new(sync.WaitGroup)
		wg.Add(nInsert)
		for j := 0; j < nInsert; j++ {
			u := rnd.Uint64()
			go func() {
				serv.Put(u, mkDefVal())
				wg.Done()
			}()
		}
		wg.Wait()

		epoch = updAuditor(t, serv, aud, epoch)
	}
	total := time.Since(start)

	m0 := float64(total.Microseconds()) / float64(nOps)
	m1 := float64(total.Milliseconds())
	benchutil.Report(nOps, []*benchutil.Metric{
		{N: m0, Unit: "us/op"},
		{N: m1, Unit: "total(ms)"},
	})
}

func TestBenchAuditSize(t *testing.T) {
	serv, rnd, _, _ := seedServer(defNSeed)
	var epoch uint64
	for ; ; epoch++ {
		_, err := serv.Audit(epoch)
		if err {
			break
		}
	}

	nInsert := 1_000
	wg := new(sync.WaitGroup)
	wg.Add(nInsert)
	for i := 0; i < nInsert; i++ {
		u := rnd.Uint64()
		go func() {
			serv.Put(u, mkDefVal())
			wg.Done()
		}()
	}
	wg.Wait()

	sz := 0
	// it takes ~3 (not 1) epochs to insert 1000, which only adds ~30B overhead.
	for ; ; epoch++ {
		upd, err := serv.Audit(epoch)
		if err {
			break
		}
		p := &ServerAuditReply{P: upd, Err: err}
		pb := ServerAuditReplyEncode(nil, p)
		sz += len(pb)
	}

	benchutil.Report(1, []*benchutil.Metric{
		{N: float64(sz), Unit: "B"},
	})
}

func TestBenchStorage(t *testing.T) {
	serv, _, _ := NewServer()
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)
	nInsert := 2_000_000
	nMeasure := 100_000
	var stat runtime.MemStats

	for i := 0; i < nInsert; i += nMeasure {
		wg := new(sync.WaitGroup)
		wg.Add(nMeasure)
		for j := 0; j < nMeasure; j++ {
			u := rnd.Uint64()
			go func() {
				serv.Put(u, mkDefVal())
				wg.Done()
			}()
		}
		wg.Wait()

		runtime.GC()
		runtime.ReadMemStats(&stat)
		mb := float64(stat.Alloc) / float64(1_000_000)
		benchutil.Report(i+nMeasure, []*benchutil.Metric{
			{N: mb, Unit: "MB"},
		})
	}
}

func updAuditor(t *testing.T, serv *Server, aud *Auditor, epoch uint64) uint64 {
	for ; ; epoch++ {
		p, err := serv.Audit(epoch)
		if err {
			break
		}
		if err = aud.Update(p); err {
			t.Fatal()
		}
	}
	return epoch
}

func seedServer(nSeed int) (*Server, *rand.ChaCha8, *cryptoffi.VrfPublicKey, []uint64) {
	serv, _, vrfPk := NewServer()
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)

	uids := make([]uint64, 0, nSeed)
	wg := new(sync.WaitGroup)
	wg.Add(nSeed)
	for i := 0; i < nSeed; i++ {
		u := rnd.Uint64()
		uids = append(uids, u)
		go func() {
			serv.Put(u, mkDefVal())
			wg.Done()
		}()
	}
	wg.Wait()
	runtime.GC()
	return serv, rnd, vrfPk, uids
}

func mkDefVal() []byte {
	// ed25519 pk is 32 bytes.
	v := make([]byte, 32)
	for i := 0; i < 32; i++ {
		v[i] = 2
	}
	return v
}
