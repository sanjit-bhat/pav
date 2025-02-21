package kt

// NOTE: for server benches that strive for akd compat,
// look for "benchmark:" in source files to find where to remove signatures.

import (
	"math/rand/v2"
	"net"
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

func TestBenchPutOne(t *testing.T) {
	serv, rnd, _, _, _ := seedServer(defNSeed)
	nOps := 2_000

	start := time.Now()
	for i := 0; i < nOps; i++ {
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

func TestBenchPutScale(t *testing.T) {
	// use big seed to minimize effects of growing puts on server.
	nSeed := 1_000_000
	serv, _, _, _, _ := seedServer(nSeed)
	// need lots of clients to hit max workq rate.
	maxNCli := 200
	var cliLats [][]float64
	for i := 0; i < maxNCli; i++ {
		cliLats = append(cliLats, make([]float64, 0, 1_000_000))
	}
	// TODO: size for tput on sr4.
	sample := &stats.Sample{Xs: make([]float64, 0, 10_000_000)}

	for nCli := 1; nCli <= maxNCli; nCli++ {
		totalTime := runClients(nCli, cliLats, sample, func() {
			serv.Put(rand.Uint64(), mkDefVal())
		})

		ops := int(sample.Weight())
		tput := float64(ops) / totalTime.Seconds()
		benchutil.Report(ops, []*benchutil.Metric{
			{N: float64(nCli), Unit: "nCli"},
			{N: tput, Unit: "op/s"},
			{N: sample.Mean(), Unit: "mean(us)"},
			{N: sample.StdDev(), Unit: "stddev"},
			{N: sample.Quantile(0.99), Unit: "p99"},
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

	clients := make([]*Client, 0, nOps)
	for i := 0; i < nOps; i++ {
		u := rnd.Uint64()
		c := NewClient(u, servAddr, sigPk, vrfPkB)
		clients = append(clients, c)
	}

	start := time.Now()
	for i := 0; i < nOps; i++ {
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

	start := time.Now()
	for i := 0; i < nOps; i++ {
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
	var cliLats [][]float64
	for i := 0; i < maxNCli; i++ {
		cliLats = append(cliLats, make([]float64, 0, 1_000_000))
	}
	sample := &stats.Sample{Xs: make([]float64, 0, 10_000_000)}

	for nCli := 1; nCli <= maxNCli; nCli++ {
		totalTime := runClients(nCli, cliLats, sample, func() {
			u := uids[rand.IntN(nSeed)]
			serv.Get(u)
		})

		ops := int(sample.Weight())
		tput := float64(ops) / totalTime.Seconds()
		benchutil.Report(ops, []*benchutil.Metric{
			{N: float64(nCli), Unit: "nCli"},
			{N: tput, Unit: "op/s"},
			{N: sample.Mean(), Unit: "mean(us)"},
			{N: sample.StdDev(), Unit: "stddev"},
			{N: sample.Quantile(0.99), Unit: "p99"},
		})
	}
}

func TestBenchGetSize(t *testing.T) {
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

func TestBenchGetCli(t *testing.T) {
	serv, rnd, sigPk, vrfPk, uids := seedServer(defNSeed)
	vrfPkB := cryptoffi.VrfPublicKeyEncode(vrfPk)
	servRpc := NewRpcServer(serv)
	servAddr := makeUniqueAddr()
	servRpc.Serve(servAddr)
	time.Sleep(time.Millisecond)
	cli := NewClient(rnd.Uint64(), servAddr, sigPk, vrfPkB)
	nOps := 3_000

	start := time.Now()
	for i := 0; i < nOps; i++ {
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

	start := time.Now()
	for i := 0; i < nOps; i++ {
		u := uids[i]
		serv.SelfMon(u)
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
	var cliLats [][]float64
	for i := 0; i < maxNCli; i++ {
		cliLats = append(cliLats, make([]float64, 0, 1_000_000))
	}
	sample := &stats.Sample{Xs: make([]float64, 0, 10_000_000)}

	for nCli := 1; nCli <= maxNCli; nCli++ {
		totalTime := runClients(nCli, cliLats, sample, func() {
			u := uids[rand.IntN(nSeed)]
			serv.SelfMon(u)
		})

		ops := int(sample.Weight())
		tput := float64(ops) / totalTime.Seconds()
		benchutil.Report(ops, []*benchutil.Metric{
			{N: float64(nCli), Unit: "nCli"},
			{N: tput, Unit: "op/s"},
			{N: sample.Mean(), Unit: "mean(us)"},
			{N: sample.StdDev(), Unit: "stddev"},
			{N: sample.Quantile(0.99), Unit: "p99"},
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

	clients := make([]*Client, 0, nOps)
	wg := new(sync.WaitGroup)
	wg.Add(nOps)
	for i := 0; i < nOps; i++ {
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

	start := time.Now()
	for i := 0; i < nOps; i++ {
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
	nInsert := 1_000

	var total time.Duration
	for i := 0; i < nOps; i++ {
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
	nEps := 5

	// after putting nEps keys, a client knows about nEps epochs.
	clients := make([]*Client, 0, nOps)
	wg := new(sync.WaitGroup)
	wg.Add(nOps)
	for i := 0; i < nOps; i++ {
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

	start := time.Now()
	for i := 0; i < nOps; i++ {
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

	for i := 0; i < nInsert; i += nMeasure {
		wg := new(sync.WaitGroup)
		wg.Add(nMeasure)
		start := time.Now()
		for j := 0; j < nMeasure; j++ {
			u := rnd.Uint64()
			go func() {
				serv.Put(u, mkDefVal())
				wg.Done()
			}()
		}
		wg.Wait()
		total := time.Since(start)

		runtime.GC()
		runtime.ReadMemStats(&stat)
		tput := float64(nMeasure) / float64(total.Seconds())
		mb := float64(stat.Alloc) / float64(1_000_000)
		benchutil.Report(i+nMeasure, []*benchutil.Metric{
			{N: tput, Unit: "op/s"},
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

func runClients(nCli int, lats [][]float64, sample *stats.Sample, work func()) time.Duration {
	for i := 0; i < nCli; i++ {
		lats[i] = lats[i][:0]
	}
	var finish []chan struct{}
	for i := 0; i < nCli; i++ {
		finish = append(finish, make(chan struct{}, 1))
	}
	wg := new(sync.WaitGroup)
	wg.Add(nCli)

	// run.
	start := time.Now()
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
					t := time.Since(s)
					lats[i] = append(lats[i], float64(t.Microseconds()))
				}
			}
		}()
	}

	time.Sleep(time.Second)
	for i := 0; i < nCli; i++ {
		finish[i] <- struct{}{}
	}
	wg.Wait()
	total := time.Since(start)

	// record.
	*sample = stats.Sample{Xs: sample.Xs[:0]}
	for i := 0; i < nCli; i++ {
		sample.Xs = append(sample.Xs, lats[i]...)
	}
	sample.Sort()
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
