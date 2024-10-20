package kt

// set global timing such that:
// - chaos interlaces enough with alice.
// - chaos mostly has up-to-date audits.
// - bob queries somewhere around halfway thru alice's puts.
// - before alice and bob finally check keys, the auditor has caught up.

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

	// alice SelfMon + Audit. bob Audit. ordering irrelevant across clients.
	primitive.Sleep(1000_000_000)
	selfMonEp, err0 := aliceCli.SelfMon()
	primitive.Assume(!err0.err)
	// could also state this as bob.epoch <= last epoch in history.
	primitive.Assume(bob.epoch <= selfMonEp)
	err1 := aliceCli.Audit(adtr0Addr, adtr0Pk)
	primitive.Assume(!err1.err)
	err2 := aliceCli.Audit(adtr1Addr, adtr1Pk)
	primitive.Assume(!err2.err)
	err3 := bobCli.Audit(adtr0Addr, adtr0Pk)
	primitive.Assume(!err3.err)
	err4 := bobCli.Audit(adtr1Addr, adtr1Pk)
	primitive.Assume(!err4.err)

	// final check. bob got the right key.
	isReg, aliceKey := GetHist(alice.hist, bob.epoch)
	primitive.Assert(isReg == bob.isReg)
	if isReg {
		primitive.Assert(std.BytesEqual(aliceKey, bob.alicePk))
	}
}

type alice struct {
	hist []*HistEntry
}

func (a *alice) run(cli *Client) {
	for i := byte(0); i < byte(20); i++ {
		primitive.Sleep(50_000_000)
		pk := []byte{i}
		epoch, err0 := cli.Put(pk)
		primitive.Assume(!err0.err)
		a.hist = append(a.hist, &HistEntry{Epoch: epoch, HistVal: pk})
	}
}

type bob struct {
	epoch   uint64
	isReg   bool
	alicePk []byte
}

func (b *bob) run(cli *Client) {
	primitive.Sleep(550_000_000)
	isReg, pk, epoch, err0 := cli.Get(aliceUid)
	primitive.Assume(!err0.err)
	b.epoch = epoch
	b.isReg = isReg
	b.alicePk = pk
}

// chaos from Charlie running all the ops.
func chaos(charlie *Client, adtr0Addr, adtr1Addr uint64, adtr0Pk, adtr1Pk cryptoffi.PublicKey) {
	for {
		primitive.Sleep(40_000_000)
		pk := []byte{2}
		_, err0 := charlie.Put(pk)
		primitive.Assume(!err0.err)
		_, _, _, err1 := charlie.Get(aliceUid)
		primitive.Assume(!err1.err)
		_, err2 := charlie.SelfMon()
		primitive.Assume(!err2.err)
		charlie.Audit(adtr0Addr, adtr0Pk)
		charlie.Audit(adtr1Addr, adtr1Pk)
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
