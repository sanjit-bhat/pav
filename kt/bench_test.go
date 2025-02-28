package kt

// NOTE: for server benches that strive for akd compat,
// look for "benchmark:" in source files to find where to remove signatures.

import (
	"log"
	"math/rand/v2"
	"net"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/aclements/go-moremath/stats"
	"github.com/mit-pdos/pav/benchutil"
	"github.com/mit-pdos/pav/cryptoffi"
)

const (
	defNSeed uint64  = 1_000_000
	nsPerUs  float64 = 1_000
)

func TestBenchPutOne(t *testing.T) {
	serv, _, _, _ := seedServer(defNSeed)
	nOps := 6_000
	nWarm := getWarmup(nOps)

	var start time.Time
	for i := 0; i < nWarm+nOps; i++ {
		if i == nWarm {
			start = time.Now()
		}
		_, _, _, err := serv.Put(rand.Uint64(), mkRandVal())
		if err {
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

func TestBenchPutScale(t *testing.T) {
	// need lots of clients to hit max workq rate.
	maxNCli := 200
	runner := newClientRunner(maxNCli)

	for nCli := 1; nCli <= maxNCli; nCli++ {
		serv, _, _, _ := seedServer(defNSeed)
		totalTime := runner.run(nCli, func() {
			serv.Put(rand.Uint64(), mkRandVal())
		})

		ops := int(runner.sample.Weight())
		tput := float64(ops) / totalTime.Seconds()
		benchutil.Report(nCli, []*benchutil.Metric{
			{N: tput, Unit: "op/s"},
			{N: runner.sample.Mean() / nsPerUs, Unit: "mean(us)"},
			{N: runner.sample.StdDev() / nsPerUs, Unit: "stddev"},
			{N: runner.sample.Quantile(0.99) / nsPerUs, Unit: "p99"},
		})
	}
}

func TestBenchPutBatch(t *testing.T) {
	sizes := []int{1, 2, 5, 10, 20, 50, 100, 200, 500, 1_000, 2_000, 5_000}
	for _, batchSz := range sizes {
		total, nBatches := putBatchHelper(batchSz)

		tput := float64(nBatches*batchSz) / total.Seconds()
		lat := float64(total.Microseconds()) / float64(nBatches)
		overall := float64(total.Milliseconds())
		benchutil.Report(batchSz, []*benchutil.Metric{
			{N: tput, Unit: "op/s"},
			{N: lat, Unit: "us/batch"},
			{N: overall, Unit: "total(ms)"},
		})
	}
}

func putBatchHelper(batchSz int) (time.Duration, int) {
	serv, _, _, _ := seedServer(defNSeed)
	nBatches := 20
	nWarm := getWarmup(nBatches)

	start := time.Now()
	for i := 0; i < nWarm+nBatches; i++ {
		if i == nWarm {
			start = time.Now()
		}
		work := make([]*Work, 0, batchSz)
		for i := 0; i < batchSz; i++ {
			w := &Work{Req: &WQReq{Uid: rand.Uint64(), Pk: mkRandVal()}}
			work = append(work, w)
		}
		serv.workQ.DoBatch(work)
	}
	total := time.Since(start)
	return total, nBatches
}

func TestBenchPutSize(t *testing.T) {
	serv, _, _, _ := seedServer(defNSeed)
	u := rand.Uint64()
	dig, lat, bound, err := serv.Put(u, mkRandVal())
	if err {
		t.Fatal()
	}
	p := &ServerPutReply{Dig: dig, Latest: lat, Bound: bound, Err: err}
	pb := ServerPutReplyEncode(nil, p)
	benchutil.Report(1, []*benchutil.Metric{
		{N: float64(len(pb)), Unit: "B"},
	})
}

func TestBenchPutVerify(t *testing.T) {
	serv, _, vrfPk, _ := seedServer(defNSeed)
	nOps := 6_000
	nWarm := getWarmup(nOps)

	var total time.Duration
	for i := 0; i < nWarm+nOps; i++ {
		if i == nWarm {
			total = 0
		}
		uid := rand.Uint64()
		dig, lat, bound, err := serv.Put(uid, mkRandVal())
		if err {
			t.Fatal()
		}

		s := time.Now()
		if checkMemb(vrfPk, uid, 0, dig.Dig, lat) {
			t.Fatal()
		}
		if checkNonMemb(vrfPk, uid, 1, dig.Dig, bound) {
			t.Fatal()
		}
		total += time.Since(s)
	}

	m0 := float64(total.Microseconds()) / float64(nOps)
	m1 := float64(total.Milliseconds())
	benchutil.Report(nOps, []*benchutil.Metric{
		{N: m0, Unit: "us/op"},
		{N: m1, Unit: "total(ms)"},
	})
}

func TestBenchPutCli(t *testing.T) {
	serv, sigPk, vrfPk, _ := seedServer(defNSeed)
	vrfPkB := cryptoffi.VrfPublicKeyEncode(vrfPk)
	servRpc := NewRpcServer(serv)
	servAddr := makeUniqueAddr()
	servRpc.Serve(servAddr)
	time.Sleep(time.Millisecond)
	nOps := 6_000
	nWarm := getWarmup(nOps)

	clients := make([]*Client, 0, nWarm+nOps)
	for i := 0; i < nWarm+nOps; i++ {
		u := rand.Uint64()
		c := NewClient(u, servAddr, sigPk, vrfPkB)
		clients = append(clients, c)
	}

	var start time.Time
	for i := 0; i < nWarm+nOps; i++ {
		if i == nWarm {
			start = time.Now()
		}
		_, err := clients[i].Put(mkRandVal())
		if err.Err {
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

func TestBenchGetOne(t *testing.T) {
	serv, _, _, uids := seedServer(defNSeed)
	nOps := 6_000
	nWarm := getWarmup(nOps)

	var start time.Time
	for i := 0; i < nWarm+nOps; i++ {
		if i == nWarm {
			start = time.Now()
		}
		uid := uids[rand.Uint64N(defNSeed)]
		_, _, isReg, _, _ := serv.Get(uid)
		if !isReg {
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
	serv, _, _, uids := seedServer(defNSeed)
	maxNCli := runtime.NumCPU()
	runner := newClientRunner(maxNCli)

	for nCli := 1; nCli <= maxNCli; nCli++ {
		totalTime := runner.run(nCli, func() {
			u := uids[rand.Uint64N(defNSeed)]
			serv.Get(u)
		})

		ops := int(runner.sample.Weight())
		tput := float64(ops) / totalTime.Seconds()
		benchutil.Report(nCli, []*benchutil.Metric{
			{N: tput, Unit: "op/s"},
			{N: runner.sample.Mean() / nsPerUs, Unit: "mean(us)"},
			{N: runner.sample.StdDev() / nsPerUs, Unit: "stddev"},
			{N: runner.sample.Quantile(0.99) / nsPerUs, Unit: "p99"},
		})
	}
}

func TestBenchGetSize(t *testing.T) {
	serv, _, _, _ := seedServer(defNSeed)
	maxNVers := 10
	uid := rand.Uint64()
	for nVers := 1; nVers <= maxNVers; nVers++ {
		serv.Put(uid, mkRandVal())
		dig, hist, isReg, lat, bound := serv.Get(uid)
		if !isReg {
			t.Fatal()
		}
		p := &ServerGetReply{Dig: dig, Hist: hist, IsReg: isReg, Latest: lat, Bound: bound}
		pb := ServerGetReplyEncode(nil, p)
		benchutil.Report(nVers, []*benchutil.Metric{
			{N: float64(len(pb)), Unit: "B"},
		})
	}
}

func TestBenchGetVerify(t *testing.T) {
	maxNVers := 10
	for nVers := 1; nVers <= maxNVers; nVers++ {
		nOps, totalGen, totalVerify := getVerifyHelper(t, nVers)

		m0 := float64(totalGen.Microseconds()) / float64(nOps)
		m1 := float64(totalGen.Milliseconds())
		m2 := float64(totalVerify.Microseconds()) / float64(nOps)
		m3 := float64(totalVerify.Milliseconds())

		benchutil.Report(nVers, []*benchutil.Metric{
			{N: m0, Unit: "us/op(gen)"},
			{N: m1, Unit: "total(ms,gen)"},
			{N: m2, Unit: "us/op(ver)"},
			{N: m3, Unit: "total(ms,ver)"},
		})
	}
}

func getVerifyHelper(t *testing.T, nVers int) (int, time.Duration, time.Duration) {
	serv, _, vrfPk, _ := seedServer(defNSeed)
	nOps := 6_000
	nWarm := getWarmup(nOps)
	var totalGen time.Duration
	var totalVerify time.Duration

	for i := 0; i < nWarm+nOps; i++ {
		if i == nWarm {
			totalGen = 0
			totalVerify = 0
		}

		uid := rand.Uint64()
		for j := 0; j < nVers; j++ {
			serv.Put(uid, mkRandVal())
		}

		s0 := time.Now()
		dig, hist, isReg, lat, bound := serv.Get(uid)
		totalGen += time.Since(s0)

		if !isReg {
			t.Fatal()
		}
		if len(hist) != nVers-1 {
			t.Fatal()
		}

		s1 := time.Now()
		if checkHist(vrfPk, uid, dig.Dig, hist) {
			t.Fatal()
		}
		if checkMemb(vrfPk, uid, uint64(nVers-1), dig.Dig, lat) {
			t.Fatal()
		}
		if checkNonMemb(vrfPk, uid, uint64(nVers), dig.Dig, bound) {
			t.Fatal()
		}
		totalVerify += time.Since(s1)
	}

	return nOps, totalGen, totalVerify
}

func TestBenchGetCli(t *testing.T) {
	serv, sigPk, vrfPk, uids := seedServer(defNSeed)
	vrfPkB := cryptoffi.VrfPublicKeyEncode(vrfPk)
	servRpc := NewRpcServer(serv)
	servAddr := makeUniqueAddr()
	servRpc.Serve(servAddr)
	time.Sleep(time.Millisecond)
	cli := NewClient(rand.Uint64(), servAddr, sigPk, vrfPkB)
	nOps := 6_000
	nWarm := getWarmup(nOps)

	var start time.Time
	for i := 0; i < nWarm+nOps; i++ {
		if i == nWarm {
			start = time.Now()
		}
		uid := uids[rand.Uint64N(defNSeed)]
		isReg, _, _, err := cli.Get(uid)
		if err.Err {
			t.Fatal()
		}
		if !isReg {
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

func TestBenchSelfMonOne(t *testing.T) {
	serv, _, _, uids := seedServer(defNSeed)
	nOps := 6_000
	nWarm := getWarmup(nOps)

	var start time.Time
	for i := 0; i < nWarm+nOps; i++ {
		if i == nWarm {
			start = time.Now()
		}
		uid := uids[rand.Uint64N(defNSeed)]
		serv.SelfMon(uid)
	}
	total := time.Since(start)

	m0 := float64(total.Microseconds()) / float64(nOps)
	m1 := float64(total.Milliseconds())
	benchutil.Report(nOps, []*benchutil.Metric{
		{N: m0, Unit: "us/op"},
		{N: m1, Unit: "total(ms)"},
	})
}

func TestBenchSelfMonScale(t *testing.T) {
	serv, _, _, uids := seedServer(defNSeed)
	maxNCli := runtime.NumCPU()
	runner := newClientRunner(maxNCli)

	for nCli := 1; nCli <= maxNCli; nCli++ {
		totalTime := runner.run(nCli, func() {
			u := uids[rand.Uint64N(defNSeed)]
			serv.SelfMon(u)
		})

		ops := int(runner.sample.Weight())
		tput := float64(ops) / totalTime.Seconds()
		benchutil.Report(nCli, []*benchutil.Metric{
			{N: tput, Unit: "op/s"},
			{N: runner.sample.Mean() / nsPerUs, Unit: "mean(us)"},
			{N: runner.sample.StdDev() / nsPerUs, Unit: "stddev"},
			{N: runner.sample.Quantile(0.99) / nsPerUs, Unit: "p99"},
		})
	}
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

func TestBenchSelfMonVerify(t *testing.T) {
	serv, _, vrfPk, uids := seedServer(defNSeed)
	nOps := 6_000
	nWarm := getWarmup(nOps)

	var total time.Duration
	for i := 0; i < nWarm+nOps; i++ {
		if i == nWarm {
			total = 0
		}
		uid := uids[rand.Uint64N(defNSeed)]
		dig, bound := serv.SelfMon(uid)

		s := time.Now()
		if checkNonMemb(vrfPk, uid, 1, dig.Dig, bound) {
			t.Fatal()
		}
		total += time.Since(s)
	}

	m0 := float64(total.Microseconds()) / float64(nOps)
	m1 := float64(total.Milliseconds())
	benchutil.Report(nOps, []*benchutil.Metric{
		{N: m0, Unit: "us/op"},
		{N: m1, Unit: "total(ms)"},
	})
}

func TestBenchSelfMonCli(t *testing.T) {
	serv, sigPk, vrfPk, _ := seedServer(defNSeed)
	vrfPkB := cryptoffi.VrfPublicKeyEncode(vrfPk)
	servRpc := NewRpcServer(serv)
	servAddr := makeUniqueAddr()
	servRpc.Serve(servAddr)
	time.Sleep(time.Millisecond)
	nOps := 6_000
	nWarm := getWarmup(nOps)

	clients := make([]*Client, 0, nWarm+nOps)
	wg := new(sync.WaitGroup)
	wg.Add(nWarm + nOps)
	for i := 0; i < nWarm+nOps; i++ {
		u := rand.Uint64()
		c := NewClient(u, servAddr, sigPk, vrfPkB)
		clients = append(clients, c)
		go func() {
			_, err := c.Put(mkRandVal())
			if err.Err {
				t.Error()
			}
			wg.Done()
		}()
	}
	wg.Wait()

	var start time.Time
	for i := 0; i < nWarm+nOps; i++ {
		if i == nWarm {
			start = time.Now()
		}
		_, err := clients[i].SelfMon()
		if err.Err {
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

func TestBenchAuditBatch(t *testing.T) {
	serv, _, _, _ := seedServer(defNSeed)
	aud, _ := NewAuditor()
	epoch := updAuditor(t, serv, aud, 0)
	nOps := 500
	nWarm := getWarmup(nOps)
	nInsert := 1_000

	var total time.Duration
	for i := 0; i < nWarm+nOps; i++ {
		if i == nWarm {
			total = 0
		}
		work := make([]*Work, 0, nInsert)
		for j := 0; j < nInsert; j++ {
			w := &Work{Req: &WQReq{Uid: rand.Uint64(), Pk: mkRandVal()}}
			work = append(work, w)
		}
		serv.workQ.DoBatch(work)

		s := time.Now()
		epoch = updAuditor(t, serv, aud, epoch)
		total += time.Since(s)
	}

	m0 := float64(total.Microseconds()) / float64(nOps)
	m1 := float64(total.Milliseconds())
	benchutil.Report(nOps, []*benchutil.Metric{
		{N: m0, Unit: "us/op"},
		{N: m1, Unit: "total(ms)"},
	})
}

func TestBenchAuditSize(t *testing.T) {
	serv, _, _, _ := seedServer(defNSeed)
	var epoch uint64
	for ; ; epoch++ {
		_, err := serv.Audit(epoch)
		if err {
			break
		}
	}

	nInsert := 1_000
	work := make([]*Work, 0, nInsert)
	for j := 0; j < nInsert; j++ {
		w := &Work{Req: &WQReq{Uid: rand.Uint64(), Pk: mkRandVal()}}
		work = append(work, w)
	}
	serv.workQ.DoBatch(work)

	upd, err := serv.Audit(epoch)
	p := &ServerAuditReply{P: upd, Err: err}
	pb := ServerAuditReplyEncode(nil, p)

	epoch++
	_, err = serv.Audit(epoch)
	// prev updates should have all been processed in 1 epoch.
	if !err {
		t.Fatal()
	}

	benchutil.Report(1, []*benchutil.Metric{
		{N: float64(len(pb)), Unit: "B"},
	})
}

func TestBenchAuditCli(t *testing.T) {
	serv, sigPk, vrfPk, _ := seedServer(defNSeed)
	vrfPkB := cryptoffi.VrfPublicKeyEncode(vrfPk)
	servRpc := NewRpcServer(serv)
	servAddr := makeUniqueAddr()
	servRpc.Serve(servAddr)
	time.Sleep(time.Millisecond)
	nOps := 6_000
	nWarm := getWarmup(nOps)
	nEps := 5

	// after putting nEps keys, a client knows about nEps epochs.
	clients := make([]*Client, 0, nWarm+nOps)
	wg := new(sync.WaitGroup)
	wg.Add(nWarm + nOps)
	for i := 0; i < nWarm+nOps; i++ {
		c := NewClient(rand.Uint64(), servAddr, sigPk, vrfPkB)
		clients = append(clients, c)

		go func() {
			for j := 0; j < nEps; j++ {
				_, err := c.Put(mkRandVal())
				if err.Err {
					t.Error()
				}
			}
			wg.Done()
		}()
	}
	wg.Wait()

	aud, audPk := NewAuditor()
	updAuditor(t, serv, aud, 0)
	audRpc := NewRpcAuditor(aud)
	audAddr := makeUniqueAddr()
	audRpc.Serve(audAddr)
	time.Sleep(time.Millisecond)

	var start time.Time
	for i := 0; i < nWarm+nOps; i++ {
		if i == nWarm {
			start = time.Now()
		}
		err := clients[i].Audit(audAddr, audPk)
		if err.Err {
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

func TestBenchServScale(t *testing.T) {
	serv, _, _ := NewServer()
	nInsert := 236_500_000
	nMeasure := 500_000
	var stat runtime.MemStats
	nCli := 100
	runner := newClientRunner(nCli)

	for i := 0; i < nInsert; i += nMeasure {
		totalTime := runner.run(nCli, func() {
			serv.Put(rand.Uint64(), mkRandVal())
		})

		nRem := i + nMeasure - len(serv.visKeys)
		work := make([]*Work, 0, nRem)
		for j := 0; j < nRem; j++ {
			w := &Work{Req: &WQReq{Uid: rand.Uint64(), Pk: mkRandVal()}}
			work = append(work, w)
		}
		serv.workQ.DoBatch(work)

		runtime.GC()
		runtime.ReadMemStats(&stat)
		mb := float64(stat.Alloc) / float64(1_000_000)
		ops := int(runner.sample.Weight())
		tput := float64(ops) / totalTime.Seconds()
		benchutil.Report(i+nMeasure, []*benchutil.Metric{
			{N: tput, Unit: "op/s"},
			{N: runner.sample.Mean() / nsPerUs, Unit: "mean(us)"},
			{N: runner.sample.StdDev() / nsPerUs, Unit: "stddev"},
			{N: runner.sample.Quantile(0.99) / nsPerUs, Unit: "p99"},
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

func seedServer(nSeed uint64) (*Server, cryptoffi.SigPublicKey, *cryptoffi.VrfPublicKey, []uint64) {
	serv, sigPk, vrfPk := NewServer()
	uids := make([]uint64, 0, nSeed)

	// use multiple epochs for akd bench parity.
	nEp := uint64(65_536)
	if nSeed < nEp {
		log.Fatal("nSeed too small")
	}
	for i := uint64(0); i < nEp; i++ {
		u := rand.Uint64()
		uids = append(uids, u)
		w := &Work{Req: &WQReq{Uid: u, Pk: mkRandVal()}}
		serv.workQ.Do(w)
	}

	work := make([]*Work, 0, nSeed-nEp)
	for i := uint64(0); i < nSeed-nEp; i++ {
		u := rand.Uint64()
		uids = append(uids, u)
		work = append(work, &Work{Req: &WQReq{Uid: u, Pk: mkRandVal()}})
	}
	serv.workQ.DoBatch(work)
	runtime.GC()
	return serv, sigPk, vrfPk, uids
}

type clientRunner struct {
	times  [][]startEnd
	sample *stats.Sample
}

type startEnd struct {
	start time.Time
	end   time.Time
}

func newClientRunner(maxNCli int) *clientRunner {
	var times [][]startEnd
	for i := 0; i < maxNCli; i++ {
		times = append(times, make([]startEnd, 0, 1_000_000))
	}
	sample := &stats.Sample{Xs: make([]float64, 0, 10_000_000)}
	return &clientRunner{times: times, sample: sample}
}

func (c *clientRunner) run(nCli int, work func()) time.Duration {
	// get data.
	for i := 0; i < nCli; i++ {
		c.times[i] = c.times[i][:0]
	}
	wg := new(sync.WaitGroup)
	wg.Add(nCli)
	for i := 0; i < nCli; i++ {
		go func() {
			cliStart := time.Now()
			for {
				s := time.Now()
				work()
				e := time.Now()
				c.times[i] = append(c.times[i], startEnd{start: s, end: e})

				if e.Sub(cliStart) >= time.Second {
					wg.Done()
					break
				}
			}
		}()
	}
	wg.Wait()

	// clamp starts and ends to account for setup and takedown variance.
	starts := make([]time.Time, 0, nCli)
	ends := make([]time.Time, 0, nCli)
	for i := 0; i < nCli; i++ {
		ts := c.times[i]
		starts = append(starts, ts[0].start)
		ends = append(ends, ts[len(ts)-1].end)
	}
	init := slices.MaxFunc(starts, func(s, e time.Time) int {
		return s.Compare(e)
	})
	postWarm := init.Add(100 * time.Millisecond)
	end := slices.MinFunc(ends, func(s, e time.Time) int {
		return s.Compare(e)
	})
	total := end.Sub(postWarm)

	// extract sample from between warmup and ending time.
	*c.sample = stats.Sample{Xs: c.sample.Xs[:0]}
	for i := 0; i < nCli; i++ {
		times := c.times[i]
		low, _ := slices.BinarySearchFunc(times, postWarm,
			func(s startEnd, t time.Time) int {
				return s.start.Compare(t)
			})
		high, ok := slices.BinarySearchFunc(times, end,
			func(s startEnd, t time.Time) int {
				return s.end.Compare(t)
			})
		if ok {
			high++
		}
		if high-low < 1_000 {
			log.Fatal("clientRunner: clients don't have enough overlapping samples")
		}
		for j := low; j < high; j++ {
			d := float64(times[j].end.Sub(times[j].start).Nanoseconds())
			c.sample.Xs = append(c.sample.Xs, d)
		}
	}
	c.sample.Sort()
	return total
}

func mkRandVal() []byte {
	// ed25519 pk is 32 bytes.
	x := make([]byte, 32)
	RandRead(x)
	return x
}

func getFreePort() (port uint64, err error) {
	var a *net.TCPAddr
	if a, err = net.ResolveTCPAddr("tcp", "localhost:0"); err == nil {
		var l *net.TCPListener
		if l, err = net.ListenTCP("tcp", a); err == nil {
			defer l.Close()
			return uint64(l.Addr().(*net.TCPAddr).Port), nil
		}
	}
	return
}

func makeUniqueAddr() uint64 {
	port, err := getFreePort()
	if err != nil {
		panic("bad port")
	}
	// left shift to make IP 0.0.0.0.
	return port << 32
}

func getWarmup(nOps int) int {
	return int(float64(nOps) * float64(0.1))
}

func LEPutUint64(b []byte, v uint64) {
	_ = b[7] // early bounds check to guarantee safety of writes below
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	b[6] = byte(v >> 48)
	b[7] = byte(v >> 56)
}

func RandRead(p []byte) {
	for len(p) >= 8 {
		LEPutUint64(p, rand.Uint64())
		p = p[8:]
	}
	if len(p) > 0 {
		b := make([]byte, 8)
		LEPutUint64(b, rand.Uint64())
		copy(p, b)
	}
}
