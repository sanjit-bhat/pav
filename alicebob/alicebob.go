package alicebob

import (
	"sync"

	"github.com/goose-lang/primitive"
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/auditor"
	"github.com/mit-pdos/pav/client"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/server"
)

const (
	aliceUid uint64 = 0
	bobUid   uint64 = 1
)

// setupParams describes different security configs with the
// servGood and adtrGood params.
type setupParams struct {
	servGood  bool
	servAddr  uint64
	servSigPk cryptoffi.SigPublicKey
	servVrfPk []byte
	adtrGood  bool
	adtrAddrs []uint64
	adtrPks   []cryptoffi.SigPublicKey
}

// testSecurity Assume's no errors in client-server calls and
// has clients contact the auditor.
func testSecurity(servAddr uint64, adtrAddrs []uint64) {
	s := setup(servAddr, adtrAddrs)
	s.servGood = false
	s.adtrGood = true
	testAliceBob(s)
}

// testCorrectness Assert's no errors in client-server calls and
// does not use auditors.
func testCorrectness(servAddr uint64, adtrAddrs []uint64) {
	s := setup(servAddr, adtrAddrs)
	s.servGood = true
	s.adtrGood = false
	testAliceBob(s)
}

func checkEvidErr(servGood bool, servPk cryptoffi.SigPublicKey, err *client.ClientErr) {
	if err.Evid != nil {
		std.Assert(!err.Evid.Check(servPk))
	}

	if servGood {
		std.Assert(!err.Err)
	} else {
		primitive.Assume(!err.Err)
	}
}

func testAliceBob(setup *setupParams) {
	aliceCli := client.NewClient(aliceUid, setup.servAddr, setup.servSigPk, setup.servVrfPk)
	alice := &alice{servGood: setup.servGood, servSigPk: setup.servSigPk, cli: aliceCli}
	bobCli := client.NewClient(bobUid, setup.servAddr, setup.servSigPk, setup.servVrfPk)
	bob := &bob{servGood: setup.servGood, servSigPk: setup.servSigPk, cli: bobCli}

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
	isInsert, _, err0 := alice.cli.SelfMon()
	checkEvidErr(setup.servGood, setup.servSigPk, err0)
	// alice has no keys in flight.
	std.Assert(!isInsert)
	alice.hist = extendHist(alice.hist, alice.cli.NextEpoch)

	if setup.adtrGood {
		// sync auditors. in real world, this'll happen periodically.
		updAdtrsAll(setup.servAddr, setup.adtrAddrs)

		// alice and bob audit. ordering irrelevant across clients.
		doAudits(alice.cli, setup.adtrAddrs, setup.adtrPks)
		doAudits(bob.cli, setup.adtrAddrs, setup.adtrPks)
	}

	// final check. bob got the right key.
	primitive.Assume(bob.cli.NextEpoch <= alice.cli.NextEpoch)
	aliceKey := alice.hist[bob.cli.NextEpoch-1]
	std.Assert(aliceKey.isReg == bob.isReg)
	if aliceKey.isReg {
		std.Assert(std.BytesEqual(aliceKey.pk, bob.alicePk))
	}
}

type alice struct {
	servGood  bool
	servSigPk cryptoffi.SigPublicKey
	cli       *client.Client
	hist      []*histEntry
}

func (a *alice) run() {
	for i := uint64(0); i < uint64(20); i++ {
		primitive.Sleep(5_000_000)
		pk := cryptoffi.RandBytes(32)
		// true bc alice waits until her old key is inserted before
		// inserting a new one.
		std.Assert(!a.cli.Put(pk))

		var isPending = true
		for isPending {
			isInsert, insertEp, err0 := a.cli.SelfMon()
			checkEvidErr(a.servGood, a.servSigPk, err0)
			if isInsert {
				// extend to insertEp-1, leaving space for latest key.
				a.hist = extendHist(a.hist, insertEp)
				a.hist = append(a.hist, &histEntry{isReg: true, pk: pk})
				a.hist = extendHist(a.hist, a.cli.NextEpoch)
				isPending = false
			}
		}
	}
}

type bob struct {
	servGood  bool
	servSigPk cryptoffi.SigPublicKey
	cli       *client.Client
	isReg     bool
	alicePk   []byte
}

func (b *bob) run() {
	primitive.Sleep(120_000_000)
	isReg, pk, err0 := b.cli.Get(aliceUid)
	checkEvidErr(b.servGood, b.servSigPk, err0)
	b.isReg = isReg
	b.alicePk = pk
}

// setup starts server and auditors.
func setup(servAddr uint64, adtrAddrs []uint64) *setupParams {
	serv, servSigPk, servVrfPk := server.NewServer()
	servVrfPkEnc := cryptoffi.VrfPublicKeyEncode(servVrfPk)
	servRpc := server.NewRpcServer(serv)
	servRpc.Serve(servAddr)
	var adtrPks []cryptoffi.SigPublicKey
	for _, adtrAddr := range adtrAddrs {
		adtr, adtrPk := auditor.NewAuditor()
		adtrRpc := auditor.NewRpcAuditor(adtr)
		adtrRpc.Serve(adtrAddr)
		adtrPks = append(adtrPks, adtrPk)
	}
	primitive.Sleep(1_000_000)
	return &setupParams{servGood: true, servAddr: servAddr, servSigPk: servSigPk, servVrfPk: servVrfPkEnc, adtrGood: true, adtrAddrs: adtrAddrs, adtrPks: adtrPks}
}
