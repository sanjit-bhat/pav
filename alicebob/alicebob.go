package alicebob

import (
	"github.com/goose-lang/primitive"
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/kt"
	"sync"
)

const (
	aliceUid uint64 = 0
	bobUid   uint64 = 1
)

// testSecurity Assume's no errors in client-server calls and
// has clients contact the auditor.
func testSecurity(servAddr uint64, adtrAddrs []uint64) {
	s := setup(servAddr, adtrAddrs)
	s.servGood = false
	testAliceBob(s)
}

// testCorrectness Assert's no errors in client-server calls and
// does not use auditors.
func testCorrectness(servAddr uint64, adtrAddrs []uint64) {
	s := setup(servAddr, adtrAddrs)
	s.servGood = true
	testAliceBob(s)
}

func checkServErr(servGood bool, err bool) {
	if servGood {
		primitive.Assert(!err)
	} else {
		primitive.Assume(!err)
	}
}

func testAliceBob(setup *setupParams) {
	aliceCli := kt.NewClient(aliceUid, setup.servAddr, setup.servSigPk, setup.servVrfPk)
	alice := &alice{servGood: setup.servGood, cli: aliceCli}
	bobCli := kt.NewClient(bobUid, setup.servAddr, setup.servSigPk, setup.servVrfPk)
	bob := &bob{servGood: setup.servGood, cli: bobCli}

	wg := new(sync.WaitGroup)
	wg.Add(1)
	wg.Add(1)
	// alice does a bunch of puts.
	go func() {
		alice.run()
		wg.Done()
	}()
	// bob does a get at some time in the middle of alice's puts.
	go func() {
		bob.run()
		wg.Done()
	}()
	wg.Wait()

	// alice self monitor. in real world, she'll come online at times and do this.
	selfMonEp, err0 := alice.cli.SelfMon()
	checkServErr(setup.servGood, err0.Err)
	alice.hist = extendHist(alice.hist, selfMonEp+1)

	if !setup.servGood {
		// sync auditors. in real world, this'll happen periodically.
		updAdtrsAll(setup.servAddr, setup.adtrAddrs)

		// alice and bob audit. ordering irrelevant across clients.
		doAudits(alice.cli, setup.adtrAddrs, setup.adtrPks)
		doAudits(bob.cli, setup.adtrAddrs, setup.adtrPks)
	}

	// final check. bob got the right key.
	primitive.Assume(bob.epoch <= selfMonEp)
	aliceKey := alice.hist[bob.epoch]
	std.Assert(aliceKey.isReg == bob.isReg)
	if aliceKey.isReg {
		std.Assert(std.BytesEqual(aliceKey.pk, bob.alicePk))
	}
}

type alice struct {
	servGood bool
	cli      *kt.Client
	hist     []*histEntry
}

func (a *alice) run() {
	for i := uint64(0); i < uint64(20); i++ {
		primitive.Sleep(5_000_000)
		pk := []byte{1}
		epoch, err0 := a.cli.Put(pk)
		checkServErr(a.servGood, err0.Err)
		// extend to numEpochs-1, leaving space for latest change.
		a.hist = extendHist(a.hist, epoch)
		a.hist = append(a.hist, &histEntry{isReg: true, pk: pk})
	}
}

type bob struct {
	servGood bool
	cli      *kt.Client
	epoch    uint64
	isReg    bool
	alicePk  []byte
}

func (b *bob) run() {
	primitive.Sleep(120_000_000)
	isReg, pk, epoch, err0 := b.cli.Get(aliceUid)
	checkServErr(b.servGood, err0.Err)
	b.epoch = epoch
	b.isReg = isReg
	b.alicePk = pk
}
