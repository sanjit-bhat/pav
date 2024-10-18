package kt

import (
	"github.com/goose-lang/primitive"
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/advrpc"
	"github.com/mit-pdos/pav/cryptoffi"
)

type setupParams struct {
	servAddr  uint64
	servSigPk cryptoffi.PublicKey
	servVrfPk *cryptoffi.VrfPublicKey
	adtrAddrs []uint64
	adtrPks   []cryptoffi.PublicKey
}

func testBasicFull(servAddr uint64, adtrAddrs []uint64) {
	testBasic(setup(servAddr, adtrAddrs))
}

// setup starts server and auditors. it's mainly a logical convenience.
// it consolidates the external parties, letting us more easily describe
// different adversary configs.
func setup(servAddr uint64, adtrAddrs []uint64) *setupParams {
	serv, servSigPk, servVrfPk := newServer()
	servRpc := newRpcServer(serv)
	servRpc.Serve(servAddr)
	var adtrPks []cryptoffi.PublicKey
	for _, adtrAddr := range adtrAddrs {
		adtr, adtrPk := newAuditor(servSigPk)
		adtrRpc := newRpcAuditor(adtr)
		adtrRpc.Serve(adtrAddr)
		adtrPks = append(adtrPks, adtrPk)
	}
	primitive.Sleep(1_000_000)
	return &setupParams{servAddr: servAddr, servSigPk: servSigPk, servVrfPk: servVrfPk, adtrAddrs: adtrAddrs, adtrPks: adtrPks}
}

func testBasic(setup *setupParams) {
	// alice put.
	alice := newClient(aliceUid, setup.servAddr, setup.servSigPk, setup.servVrfPk)
	pk0 := []byte{3}
	ep0, err0 := alice.Put(pk0)
	primitive.Assume(!err0.err)

	// update auditors.
	servCli := advrpc.Dial(setup.servAddr)
	upd0, err1 := callServAudit(servCli, 0)
	primitive.Assume(!err1)
	upd1, err2 := callServAudit(servCli, 1)
	primitive.Assume(!err2)

	adtrs := mkRpcClients(setup.adtrAddrs)
	updAdtrs(upd0, adtrs)
	updAdtrs(upd1, adtrs)

	// bob get.
	bob := newClient(bobUid, setup.servAddr, setup.servSigPk, setup.servVrfPk)
	isReg, pk1, ep1, err3 := bob.Get(aliceUid)
	primitive.Assume(!err3.err)
	// same epoch to avoid timeseries for basic TC.
	primitive.Assume(ep0 == ep1)

	// alice and bob audit.
	doAudits(alice, setup.adtrAddrs, setup.adtrPks)
	doAudits(bob, setup.adtrAddrs, setup.adtrPks)

	// assert keys equal.
	primitive.Assert(isReg)
	primitive.Assert(std.BytesEqual(pk0, pk1))
}

func mkRpcClients(addrs []uint64) []*advrpc.Client {
	var c []*advrpc.Client
	for _, addr := range addrs {
		cli := advrpc.Dial(addr)
		c = append(c, cli)
	}
	return c
}

func updAdtrs(upd *UpdateProof, adtrs []*advrpc.Client) {
	for _, cli := range adtrs {
		err := callAdtrUpdate(cli, upd)
		primitive.Assume(!err)
	}
}

func doAudits(cli *Client, adtrAddrs []uint64, adtrPks []cryptoffi.PublicKey) {
	for i := uint64(0); i < uint64(len(adtrAddrs)); i++ {
		addr := adtrAddrs[i]
		pk := adtrPks[i]
		err := cli.Audit(addr, pk)
		primitive.Assume(!err.err)
	}
}
