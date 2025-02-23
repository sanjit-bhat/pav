package kt

// NOTE: for server benches that strive for akd compat,
// look for "benchmark:" in source files to find where to remove signatures.

import (
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
	defNSeed int = 100_000
)

func TestBenchSeed(t *testing.T) {
	start := time.Now()
	seedServer(1_000_000)
	total := time.Since(start)
	t.Log(total)
}

func TestBenchPutOne(t *testing.T) {
	serv, rnd, _, _, _ := seedServer(defNSeed)
	nOps := 2_000
	nWarm := getWarmup(nOps)

	var start time.Time
	for i := 0; i < nWarm+nOps; i++ {
		if i == nWarm {
			start = time.Now()
		}
		_, _, _, err := serv.Put(rnd.Uint64(), mkDefVal())
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

func TestBenchPutBatch(t *testing.T) {
	serv, rnd, _, _, _ := seedServer(defNSeed)
	nOps := 100
	nWarm := getWarmup(nOps)
	nInsert := 1_000

	var start time.Time
	for i := 0; i < nWarm+nOps; i++ {
		if i == nWarm {
			start = time.Now()
		}
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

func TestBenchPutScale(t *testing.T) {
	// use big seed to minimize effects of growing puts on server.
	nSeed := 1_000_000
	serv, _, _, _, _ := seedServer(nSeed)
	// need lots of clients to hit max workq rate.
	maxNCli := 200
	runner := newClientRunner(maxNCli)

	for nCli := 1; nCli <= maxNCli; nCli++ {
		totalTime := runner.run(nCli, func() {
			serv.Put(rand.Uint64(), mkDefVal())
		})

		ops := int(runner.sample.Weight())
		tput := float64(ops) / totalTime.Seconds()
		benchutil.Report(nCli, []*benchutil.Metric{
			{N: tput, Unit: "op/s"},
			{N: runner.sample.Mean(), Unit: "mean(us)"},
			{N: runner.sample.StdDev(), Unit: "stddev"},
			{N: runner.sample.Quantile(0.99), Unit: "p99"},
		})
	}
}

func TestBenchPutSize(t *testing.T) {
	serv, rnd, _, _, _ := seedServer(defNSeed)
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

func TestBenchPutCli(t *testing.T) {
	serv, rnd, sigPk, vrfPk, _ := seedServer(defNSeed)
	vrfPkB := cryptoffi.VrfPublicKeyEncode(vrfPk)
	servRpc := NewRpcServer(serv)
	servAddr := makeUniqueAddr()
	servRpc.Serve(servAddr)
	time.Sleep(time.Millisecond)
	nOps := 2_000
	nWarm := getWarmup(nOps)

	clients := make([]*Client, 0, nWarm+nOps)
	for i := 0; i < nWarm+nOps; i++ {
		u := rnd.Uint64()
		c := NewClient(u, servAddr, sigPk, vrfPkB)
		clients = append(clients, c)
	}

	var start time.Time
	for i := 0; i < nWarm+nOps; i++ {
		if i == nWarm {
			start = time.Now()
		}
		_, err := clients[i].Put(mkDefVal())
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
	serv, _, _, _, uids := seedServer(defNSeed)
	nOps := 3_000
	nWarm := getWarmup(nOps)

	var start time.Time
	for i := 0; i < nWarm+nOps; i++ {
		if i == nWarm {
			start = time.Now()
		}
		u := uids[i]
		_, _, isReg, _, _ := serv.Get(u)
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
	nSeed := defNSeed
	serv, _, _, _, uids := seedServer(nSeed)
	maxNCli := runtime.NumCPU()
	runner := newClientRunner(maxNCli)

	for nCli := 1; nCli <= maxNCli; nCli++ {
		totalTime := runner.run(nCli, func() {
			u := uids[rand.IntN(nSeed)]
			serv.Get(u)
		})

		ops := int(runner.sample.Weight())
		tput := float64(ops) / totalTime.Seconds()
		benchutil.Report(nCli, []*benchutil.Metric{
			{N: tput, Unit: "op/s"},
			{N: runner.sample.Mean(), Unit: "mean(us)"},
			{N: runner.sample.StdDev(), Unit: "stddev"},
			{N: runner.sample.Quantile(0.99), Unit: "p99"},
		})
	}
}

func TestBenchGetSizeOne(t *testing.T) {
	serv, _, _, _, uids := seedServer(defNSeed)
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

func TestBenchGetSizeMulti(t *testing.T) {
	serv, rnd, _, _, _ := seedServer(defNSeed)
	maxNVers := 10
	for nVers := 1; nVers <= maxNVers; nVers++ {
		u := rnd.Uint64()
		for i := 0; i < nVers; i++ {
			serv.Put(u, mkDefVal())
		}

		dig, hist, isReg, lat, bound := serv.Get(u)
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

func TestBenchGetCli(t *testing.T) {
	serv, rnd, sigPk, vrfPk, uids := seedServer(defNSeed)
	vrfPkB := cryptoffi.VrfPublicKeyEncode(vrfPk)
	servRpc := NewRpcServer(serv)
	servAddr := makeUniqueAddr()
	servRpc.Serve(servAddr)
	time.Sleep(time.Millisecond)
	cli := NewClient(rnd.Uint64(), servAddr, sigPk, vrfPkB)
	nOps := 3_000
	nWarm := getWarmup(nOps)

	var start time.Time
	for i := 0; i < nWarm+nOps; i++ {
		if i == nWarm {
			start = time.Now()
		}
		isReg, _, _, err := cli.Get(uids[i])
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
	serv, _, _, _, uids := seedServer(defNSeed)
	nOps := 6_000
	nWarm := getWarmup(nOps)

	var start time.Time
	for i := 0; i < nWarm+nOps; i++ {
		if i == nWarm {
			start = time.Now()
		}
		serv.SelfMon(uids[i])
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
	nSeed := defNSeed
	serv, _, _, _, uids := seedServer(nSeed)
	maxNCli := runtime.NumCPU()
	runner := newClientRunner(maxNCli)

	for nCli := 1; nCli <= maxNCli; nCli++ {
		totalTime := runner.run(nCli, func() {
			u := uids[rand.IntN(nSeed)]
			serv.SelfMon(u)
		})

		ops := int(runner.sample.Weight())
		tput := float64(ops) / totalTime.Seconds()
		benchutil.Report(nCli, []*benchutil.Metric{
			{N: tput, Unit: "op/s"},
			{N: runner.sample.Mean(), Unit: "mean(us)"},
			{N: runner.sample.StdDev(), Unit: "stddev"},
			{N: runner.sample.Quantile(0.99), Unit: "p99"},
		})
	}
}

func TestBenchSelfMonSize(t *testing.T) {
	serv, _, _, _, uids := seedServer(defNSeed)
	dig, bound := serv.SelfMon(uids[0])
	p := &ServerSelfMonReply{Dig: dig, Bound: bound}
	pb := ServerSelfMonReplyEncode(nil, p)
	benchutil.Report(1, []*benchutil.Metric{
		{N: float64(len(pb)), Unit: "B"},
	})
}

func TestBenchSelfMonCli(t *testing.T) {
	serv, rnd, sigPk, vrfPk, _ := seedServer(defNSeed)
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
		u := rnd.Uint64()
		c := NewClient(u, servAddr, sigPk, vrfPkB)
		clients = append(clients, c)
		go func() {
			_, err := c.Put(mkDefVal())
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

func TestBenchAuditOne(t *testing.T) {
	serv, rnd, _, _, _ := seedServer(defNSeed)
	aud, _ := NewAuditor()
	epoch := updAuditor(t, serv, aud, 0)
	nOps := 100
	nWarm := getWarmup(nOps)
	nInsert := 1_000

	var total time.Duration
	for i := 0; i < nWarm+nOps; i++ {
		if i == nWarm {
			total = 0
		}
		work := make([]*Work, 0, nInsert)
		for j := 0; j < nInsert; j++ {
			work = append(work, &Work{Req: &WQReq{Uid: rnd.Uint64(), Pk: mkDefVal()}})
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
	serv, rnd, _, _, _ := seedServer(defNSeed)
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
		work = append(work, &Work{Req: &WQReq{Uid: rnd.Uint64(), Pk: mkDefVal()}})
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
	serv, rnd, sigPk, vrfPk, _ := seedServer(defNSeed)
	vrfPkB := cryptoffi.VrfPublicKeyEncode(vrfPk)
	servRpc := NewRpcServer(serv)
	servAddr := makeUniqueAddr()
	servRpc.Serve(servAddr)
	time.Sleep(time.Millisecond)
	nOps := 2_000
	nWarm := getWarmup(nOps)
	nEps := 5

	// after putting nEps keys, a client knows about nEps epochs.
	clients := make([]*Client, 0, nWarm+nOps)
	wg := new(sync.WaitGroup)
	wg.Add(nWarm + nOps)
	for i := 0; i < nWarm+nOps; i++ {
		c := NewClient(rnd.Uint64(), servAddr, sigPk, vrfPkB)
		clients = append(clients, c)

		go func() {
			for j := 0; j < nEps; j++ {
				_, err := c.Put(mkDefVal())
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
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)
	nInsert := 236_500_000
	nMeasure := 500_000
	var stat runtime.MemStats
	nCli := 100
	runner := newClientRunner(nCli)

	for i := 0; i < nInsert; i += nMeasure {
		totalTime := runner.run(nCli, func() {
			serv.Put(rand.Uint64(), mkDefVal())
		})

		nRem := i + nMeasure - len(serv.visibleKeys)
		work := make([]*Work, 0, nRem)
		for j := 0; j < nRem; j++ {
			work = append(work, &Work{Req: &WQReq{Uid: rnd.Uint64(), Pk: mkDefVal()}})
		}
		serv.workQ.DoBatch(work)

		runtime.GC()
		runtime.ReadMemStats(&stat)
		mb := float64(stat.Alloc) / float64(1_000_000)
		ops := int(runner.sample.Weight())
		tput := float64(ops) / totalTime.Seconds()
		benchutil.Report(i+nMeasure, []*benchutil.Metric{
			{N: tput, Unit: "op/s"},
			{N: runner.sample.Mean(), Unit: "mean(us)"},
			{N: runner.sample.StdDev(), Unit: "stddev"},
			{N: runner.sample.Quantile(0.99), Unit: "p99"},
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

func seedServer(nSeed int) (*Server, *rand.ChaCha8, cryptoffi.SigPublicKey, *cryptoffi.VrfPublicKey, []uint64) {
	serv, sigPk, vrfPk := NewServer()
	var seed [32]byte
	rnd := rand.NewChaCha8(seed)

	uids := make([]uint64, 0, nSeed)
	work := make([]*Work, 0, nSeed)
	for i := 0; i < nSeed; i++ {
		u := rnd.Uint64()
		uids = append(uids, u)
		work = append(work, &Work{Req: &WQReq{Uid: u, Pk: mkDefVal()}})
	}
	serv.workQ.DoBatch(work)
	runtime.GC()
	return serv, rnd, sigPk, vrfPk, uids
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
	// TODO: size for tput on sr4.
	sample := &stats.Sample{Xs: make([]float64, 0, 10_000_000)}
	return &clientRunner{times: times, sample: sample}
}

func (c *clientRunner) run(nCli int, work func()) time.Duration {
	for i := 0; i < nCli; i++ {
		c.times[i] = c.times[i][:0]
	}
	var finish []chan struct{}
	for i := 0; i < nCli; i++ {
		finish = append(finish, make(chan struct{}, 1))
	}
	wg := new(sync.WaitGroup)
	wg.Add(nCli)

	// get data.
	for i := 0; i < nCli; i++ {
		go func() {
			for {
				select {
				case <-finish[i]:
					wg.Done()
					return
				default:
					s := time.Now()
					work()
					e := time.Now()
					c.times[i] = append(c.times[i], startEnd{start: s, end: e})
				}
			}
		}()
	}

	time.Sleep(time.Second)
	for i := 0; i < nCli; i++ {
		finish[i] <- struct{}{}
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
		for j := low; j < high; j++ {
			d := float64(times[j].end.Sub(times[j].start).Microseconds())
			c.sample.Xs = append(c.sample.Xs, d)
		}
	}
	c.sample.Sort()
	return total
}

func mkDefVal() []byte {
	// ed25519 pk is 32 bytes.
	v := make([]byte, 32)
	for i := 0; i < 32; i++ {
		v[i] = 2
	}
	return v
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
