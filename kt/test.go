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
	"sync"
)

const (
	aliceUid   uint64 = 0
	bobUid     uint64 = 1
	charlieUid uint64 = 2
)

func testAllFull(servAddr uint64, adtrAddrs []uint64) {
	testAll(setup(servAddr, adtrAddrs))
}

func testAll(setup *setupParams) {
	// run background threads.
	go func() {
		charlie := newClient(charlieUid, setup.servAddr, setup.servSigPk, setup.servVrfPk)
		chaos(charlie)
	}()
	go func() {
		syncAdtrs(setup.servAddr, setup.adtrAddrs)
	}()

	// run alice and bob.
	alice := &alice{}
	aliceMu := new(sync.Mutex)
	aliceMu.Lock()
	aliceCli := newClient(aliceUid, setup.servAddr, setup.servSigPk, setup.servVrfPk)
	go func() {
		alice.run(aliceCli)
		aliceMu.Unlock()
	}()
	bob := &bob{}
	bobMu := new(sync.Mutex)
	bobMu.Lock()
	bobCli := newClient(bobUid, setup.servAddr, setup.servSigPk, setup.servVrfPk)
	go func() {
		bob.run(bobCli)
		bobMu.Unlock()
	}()

	// wait for alice and bob to finish.
	aliceMu.Lock()
	bobMu.Lock()

	// alice self monitor. in real world, she'll come on-line at times and do this.
	selfMonEp, err0 := aliceCli.SelfMon()
	primitive.Assume(!err0.err)
	// this last self monitor will be our history bound.
	primitive.Assume(bob.epoch <= selfMonEp)

	// wait for auditors to catch all updates.
	primitive.Sleep(1000_000_000)

	// alice and bob Audit. ordering irrelevant across clients.
	doAudits(aliceCli, setup.adtrAddrs, setup.adtrPks)
	doAudits(bobCli, setup.adtrAddrs, setup.adtrPks)

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
	for i := uint64(0); i < uint64(20); i++ {
		primitive.Sleep(50_000_000)
		pk := []byte{byte(i)}
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

// chaos from Charlie running ops.
func chaos(charlie *Client) {
	for {
		primitive.Sleep(40_000_000)
		pk := []byte{2}
		_, err0 := charlie.Put(pk)
		primitive.Assume(!err0.err)
		_, _, _, err1 := charlie.Get(aliceUid)
		primitive.Assume(!err1.err)
		_, err2 := charlie.SelfMon()
		primitive.Assume(!err2.err)
	}
}

func syncAdtrs(servAddr uint64, adtrAddrs []uint64) {
	servCli := advrpc.Dial(servAddr)
	adtrs := mkRpcClients(adtrAddrs)
	var epoch uint64
	for {
		primitive.Sleep(1_000_000)
		upd, err := callServAudit(servCli, epoch)
		if err {
			continue
		}
		updAdtrs(upd, adtrs)
		epoch++
	}
}
