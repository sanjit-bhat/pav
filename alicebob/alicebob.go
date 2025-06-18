package alicebob

import (
	"sync"

	"github.com/goose-lang/primitive"
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/advrpc"
	"github.com/mit-pdos/pav/auditor"
	"github.com/mit-pdos/pav/client"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/ktserde"
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
	servPk    cryptoffi.SigPublicKey
	adtrGood  bool
	adtrAddrs []uint64
	adtrPks   []cryptoffi.SigPublicKey
}

// testSecurity Assume's no errors in client-server calls and
// has clients contact the auditor.
func testSecurity(servAddr uint64, adtrAddrs []uint64) {
	s := setup(servAddr, adtrAddrs, false, true)
	testAliceBob(s)
}

// testCorrectness Assert's no errors in client-server calls and
// does not use auditors.
func testCorrectness(servAddr uint64, adtrAddrs []uint64) {
	s := setup(servAddr, adtrAddrs, true, false)
	testAliceBob(s)
}

func checkWorldErr(servGood bool, err bool) {
	if servGood {
		std.Assert(!err)
	} else {
		primitive.Assume(!err)
	}
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
	aliceCli, err0 := client.New(aliceUid, setup.servAddr, setup.servPk)
	checkWorldErr(setup.servGood, err0)
	alice := &alice{servGood: setup.servGood, servSigPk: setup.servPk, cli: aliceCli}
	bobCli, err1 := client.New(bobUid, setup.servAddr, setup.servPk)
	checkWorldErr(setup.servGood, err1)
	bob := &bob{servGood: setup.servGood, servSigPk: setup.servPk, cli: bobCli}

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

	if setup.adtrGood {
		// sync auditors. in real world, this'll happen periodically.
		updAdtrsAll(setup.servGood, setup.servAddr, setup.adtrAddrs)

		// alice and bob audit. ordering irrelevant across clients.
		doAudits(alice.cli, setup.servGood, setup.servPk, setup.adtrAddrs, setup.adtrPks)
		doAudits(bob.cli, setup.servGood, setup.servPk, setup.adtrAddrs, setup.adtrPks)
	}

	// final check. bob got the right key.
	// Assume alice monitored bob's Get epoch.
	primitive.Assume(bob.cli.LastEpoch.Epoch <= alice.cli.LastEpoch.Epoch)
	aliceKey := alice.hist[bob.cli.LastEpoch.Epoch]
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

type histEntry struct {
	isReg bool
	pk    []byte
}

func (a *alice) run() {
	// in this simple example, alice is the only putter.
	// she can Assume that epochs update iff her Put executes,
	// which leads to a simple history structure.
	{
		isInsert, err0 := a.cli.SelfMon()
		checkWorldErr(a.servGood, err0)
		std.Assert(!isInsert)
		primitive.Assume(a.cli.LastEpoch.Epoch == 0)
		a.hist = append(a.hist, &histEntry{})
	}

	for i := uint64(0); i < uint64(20); i++ {
		primitive.Sleep(5_000_000)
		pk := cryptoffi.RandBytes(32)
		// true bc alice waits until her old key is inserted before
		// inserting a new one.
		std.Assert(!a.cli.Put(pk))

		var isPending = true
		for isPending {
			isInsert, err0 := a.cli.SelfMon()
			checkWorldErr(a.servGood, err0)
			if isInsert {
				primitive.Assume(a.cli.LastEpoch.Epoch == uint64(len(a.hist)))
				a.hist = append(a.hist, &histEntry{isReg: true, pk: pk})
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
	checkWorldErr(b.servGood, err0)
	b.isReg = isReg
	b.alicePk = pk
}

// setup starts server and auditors.
func setup(servAddr uint64, adtrAddrs []uint64, servGood, adtrGood bool) *setupParams {
	serv, servSigPk := server.New()
	servRpc := server.NewRpcServer(serv)
	servRpc.Serve(servAddr)
	primitive.Sleep(1_000_000)

	var adtrPks []cryptoffi.SigPublicKey
	for _, adtrAddr := range adtrAddrs {
		adtr, adtrPk, err0 := auditor.New(servAddr, servSigPk)
		checkWorldErr(servGood, err0)
		adtrRpc := auditor.NewRpcAuditor(adtr)
		adtrRpc.Serve(adtrAddr)
		adtrPks = append(adtrPks, adtrPk)
	}
	primitive.Sleep(1_000_000)
	return &setupParams{servGood: servGood, servAddr: servAddr, servPk: servSigPk, adtrGood: adtrGood, adtrAddrs: adtrAddrs, adtrPks: adtrPks}
}

func doAudits(cli *client.Client, servGood bool, servPk cryptoffi.SigPublicKey, adtrAddrs []uint64, adtrPks []cryptoffi.SigPublicKey) {
	numAdtrs := uint64(len(adtrAddrs))
	for i := uint64(0); i < numAdtrs; i++ {
		addr := adtrAddrs[i]
		pk := adtrPks[i]
		err := cli.Audit(addr, pk)
		checkEvidErr(servGood, servPk, err)
		primitive.Assume(!err.Err)
	}
}

func mkRpcClients(addrs []uint64) []*advrpc.Client {
	var c []*advrpc.Client
	for _, addr := range addrs {
		cli := advrpc.Dial(addr)
		c = append(c, cli)
	}
	return c
}

func updAdtrsOnce(servGood bool, upd *ktserde.AuditProof, adtrs []*advrpc.Client) {
	for _, cli := range adtrs {
		err := auditor.CallUpdate(cli, upd)
		checkWorldErr(servGood, err)
	}
}

func updAdtrsAll(servGood bool, servAddr uint64, adtrAddrs []uint64) {
	servCli := advrpc.Dial(servAddr)
	adtrs := mkRpcClients(adtrAddrs)
	var epoch uint64
	for {
		upd, err := server.CallAudit(servCli, epoch)
		if err {
			break
		}
		updAdtrsOnce(servGood, upd, adtrs)
		epoch++
	}
}
