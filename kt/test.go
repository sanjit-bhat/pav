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

	// alice does a bunch of puts.
	aliceCli := newClient(aliceUid, setup.servAddr, setup.servSigPk, setup.servVrfPk)
	alice := &alice{cli: aliceCli}
	// TODO: if this works, change the other ones as well.
	alice.mu = new(sync.Mutex)
	alice.mu.Lock()
	go func() {
		alice.run()
	}()
	// bob does a get.
	bobCli := newClient(bobUid, setup.servAddr, setup.servSigPk, setup.servVrfPk)
	bob := &bob{cli: bobCli}
	bob.mu = new(sync.Mutex)
	bob.mu.Lock()
	go func() {
		bob.run()
	}()

	// wait for alice and bob to finish.
	alice.mu.Lock()
	bob.mu.Lock()

	// alice self monitor. in real world, she'll come on-line at times and do this.
	selfMonEp, err0 := alice.cli.SelfMon()
	primitive.Assume(!err0.err)
	// this last self monitor will be our history bound.
	primitive.Assume(bob.epoch <= selfMonEp)

	// wait for auditors to catch all updates.
	primitive.Sleep(1000_000_000)

	// alice and bob audit. ordering irrelevant across clients.
	doAudits(alice.cli, setup.adtrAddrs, setup.adtrPks)
	doAudits(bob.cli, setup.adtrAddrs, setup.adtrPks)

	// final check. bob got the right key.
	isReg, aliceKey := GetHist(alice.hist, bob.epoch)
	primitive.Assert(isReg == bob.isReg)
	if isReg {
		primitive.Assert(std.BytesEqual(aliceKey, bob.alicePk))
	}
}

type alice struct {
	mu   *sync.Mutex
	cli  *Client
	hist []*HistEntry
}

func (a *alice) run() {
	for i := uint64(0); i < uint64(20); i++ {
		primitive.Sleep(50_000_000)
		pk := []byte{byte(i)}
		epoch, err0 := a.cli.Put(pk)
		primitive.Assume(!err0.err)
		a.hist = append(a.hist, &HistEntry{Epoch: epoch, HistVal: pk})
	}
	a.mu.Unlock()
}

type bob struct {
	mu      *sync.Mutex
	cli     *Client
	epoch   uint64
	isReg   bool
	alicePk []byte
}

func (b *bob) run() {
	primitive.Sleep(550_000_000)
	isReg, pk, epoch, err0 := b.cli.Get(aliceUid)
	primitive.Assume(!err0.err)
	b.epoch = epoch
	b.isReg = isReg
	b.alicePk = pk
	b.mu.Unlock()
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
