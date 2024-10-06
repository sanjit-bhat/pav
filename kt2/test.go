package kt2

// global timing, not relev to proofs, but relev to execution:
// - chaos every 5ms.
// - auditor sync every 1ms.
// - alice put 20 times, every 3ms.
// - bob wait 35ms (just after half of alice's times), then get.
//   should be somewhere in middle of alice's puts.
// - both wait 5ms for auditors to update.
// - alice SelfMon. both Audit. then assert pk equal.

import (
	"github.com/goose-lang/primitive"
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/advrpc"
	"github.com/mit-pdos/pav/cryptoffi"
	"sync"
)

const (
	aliceUid   uint64 = 0
	bobUid     uint64 = 1
	charlieUid uint64 = 2
)

func testAll(servAddr, adtr0Addr, adtr1Addr uint64) {
	// start server and auditors.
	serv, servSigPk, servVrfPk := newServer()
	servRpc := newRpcServer(serv)
	servRpc.Serve(servAddr)
	adtr0, adtr0Pk := newAuditor(servSigPk)
	adtr0Rpc := newRpcAuditor(adtr0)
	adtr0Rpc.Serve(adtr0Addr)
	adtr1, adtr1Pk := newAuditor(servSigPk)
	adtr1Rpc := newRpcAuditor(adtr1)
	adtr1Rpc.Serve(adtr1Addr)
	primitive.Sleep(1_000_000)

	// run background threads.
	go func() {
		charlie := newClient(charlieUid, servAddr, servSigPk, servVrfPk)
		chaos(charlie, adtr0Addr, adtr1Addr, adtr0Pk, adtr1Pk)
	}()
	go func() {
		syncAdtr(servAddr, adtr0Addr, adtr1Addr)
	}()

	// run alice and bob.
	alice := &alice{}
	aliceMu := new(sync.Mutex)
	aliceMu.Lock()
	aliceCli := newClient(aliceUid, servAddr, servSigPk, servVrfPk)
	go func() {
		alice.run(aliceCli)
		aliceMu.Unlock()
	}()
	bob := &bob{}
	bobMu := new(sync.Mutex)
	bobMu.Lock()
	bobCli := newClient(bobUid, servAddr, servSigPk, servVrfPk)
	go func() {
		bob.run(bobCli)
		bobMu.Unlock()
	}()

	// wait for alice and bob to finish.
	aliceMu.Lock()
	bobMu.Lock()

	// alice SelfMon + Audit. bob Audit. ordering irrelevant.
	primitive.Sleep(5_000_000)
	_, _, err0 := aliceCli.SelfMon()
	primitive.Assume(!err0)
	_, err1 := aliceCli.Audit(adtr0Addr, adtr0Pk)
	primitive.Assume(!err1)
	_, err2 := aliceCli.Audit(adtr1Addr, adtr1Pk)
	primitive.Assume(!err2)
	_, err3 := bobCli.Audit(adtr0Addr, adtr0Pk)
	primitive.Assume(!err3)
	_, err4 := bobCli.Audit(adtr1Addr, adtr1Pk)
	primitive.Assume(!err4)

	// final check. bob got the right key.
	isReg, aliceKey := GetTimeSeries(alice.pks, bob.epoch)
	primitive.Assert(isReg == bob.isReg)
	if isReg {
		primitive.Assert(std.BytesEqual(aliceKey, bob.alicePk))
	}
}

type alice struct {
	pks []*TimeSeriesEntry
}

func (a *alice) run(cli *Client) {
	for i := byte(0); i < byte(20); i++ {
		primitive.Sleep(3_000_000)
		pk := []byte{i}
		epoch, _, err0 := cli.Put(pk)
		primitive.Assume(!err0)
		a.pks = append(a.pks, &TimeSeriesEntry{Epoch: epoch, TSVal: pk})
	}
}

type bob struct {
	epoch   uint64
	isReg   bool
	alicePk []byte
}

func (b *bob) run(cli *Client) {
	primitive.Sleep(35_000_000)
	isReg, pk, epoch, _, err0 := cli.Get(aliceUid)
	primitive.Assume(!err0)
	b.epoch = epoch
	b.isReg = isReg
	b.alicePk = pk
}

type TimeSeriesEntry struct {
	Epoch uint64
	TSVal []byte
}

// GetTimeSeries rets whether a val is registered at the time and, if so, the val.
func GetTimeSeries(o []*TimeSeriesEntry, epoch uint64) (bool, []byte) {
	var isReg bool
	var val []byte
	// entries inv: ordered by epoch field.
	for _, e := range o {
		if e.Epoch >= epoch {
			isReg = true
			val = e.TSVal
			continue
		}
		break
	}
	return isReg, val
}

// chaos comes from Charlie running all the ops.
func chaos(charlie *Client, adtr0Addr, adtr1Addr uint64, adtr0Pk, adtr1Pk cryptoffi.PublicKey) {
	for {
		primitive.Sleep(5_000_000)
		pk := []byte{2}
		_, _, err0 := charlie.Put(pk)
		primitive.Assume(!err0)
		_, _, _, _, err1 := charlie.Get(aliceUid)
		primitive.Assume(!err1)
		_, _, err2 := charlie.SelfMon()
		primitive.Assume(!err2)
		_, err3 := charlie.Audit(adtr0Addr, adtr0Pk)
		primitive.Assume(!err3)
		_, err4 := charlie.Audit(adtr1Addr, adtr1Pk)
		primitive.Assume(!err4)
	}
}

func syncAdtr(servAddr, adtr0Addr, adtr1Addr uint64) {
	servCli := advrpc.Dial(servAddr)
	adtr0Cli := advrpc.Dial(adtr0Addr)
	adtr1Cli := advrpc.Dial(adtr1Addr)
	var epoch uint64
	for {
		primitive.Sleep(1_000_000)
		upd, err0 := callServAudit(servCli, epoch)
		if err0 {
			continue
		}
		err1 := callAdtrUpdate(adtr0Cli, upd)
		primitive.Assume(!err1)
		err2 := callAdtrUpdate(adtr1Cli, upd)
		primitive.Assume(!err2)
		epoch++
	}
}
