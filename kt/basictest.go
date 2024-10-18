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
	adtr0Addr uint64
	adtr0Pk   cryptoffi.PublicKey
	adtr1Addr uint64
	adtr1Pk   cryptoffi.PublicKey
}

// setup starts server and auditors. it's mainly a logical convenience.
// it consolidates the external parties, letting us more easily describe
// different adversary configs.
func setup(servAddr, adtr0Addr, adtr1Addr uint64) *setupParams {
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
	return &setupParams{servAddr: servAddr, servSigPk: servSigPk, servVrfPk: servVrfPk, adtr0Addr: adtr0Addr, adtr0Pk: adtr0Pk, adtr1Addr: adtr1Addr, adtr1Pk: adtr1Pk}
}

func testBasic(params *setupParams) {
	// alice put.
	alice := newClient(aliceUid, params.servAddr, params.servSigPk, params.servVrfPk)
	pk0 := []byte{3}
	ep0, err0 := alice.Put(pk0)
	primitive.Assume(!err0.err)

	// update auditors.
	servCli := advrpc.Dial(params.servAddr)
	adtr0Cli := advrpc.Dial(params.adtr0Addr)
	adtr1Cli := advrpc.Dial(params.adtr1Addr)
	upd0, err1 := callServAudit(servCli, 0)
	primitive.Assume(!err1)
	upd1, err2 := callServAudit(servCli, 1)
	primitive.Assume(!err2)
	err3 := callAdtrUpdate(adtr0Cli, upd0)
	primitive.Assume(!err3)
	err4 := callAdtrUpdate(adtr0Cli, upd1)
	primitive.Assume(!err4)
	err5 := callAdtrUpdate(adtr1Cli, upd0)
	primitive.Assume(!err5)
	err6 := callAdtrUpdate(adtr1Cli, upd1)
	primitive.Assume(!err6)

	// bob get.
	bob := newClient(bobUid, params.servAddr, params.servSigPk, params.servVrfPk)
	isReg, pk1, ep1, err7 := bob.Get(aliceUid)
	primitive.Assume(!err7.err)
	// same epoch to avoid timeseries for basic TC.
	primitive.Assume(ep0 == ep1)

	// alice and bob audit.
	err8 := alice.Audit(params.adtr0Addr, params.adtr0Pk)
	primitive.Assume(!err8.err)
	err9 := alice.Audit(params.adtr1Addr, params.adtr1Pk)
	primitive.Assume(!err9.err)
	err10 := bob.Audit(params.adtr0Addr, params.adtr0Pk)
	primitive.Assume(!err10.err)
	err11 := bob.Audit(params.adtr1Addr, params.adtr1Pk)
	primitive.Assume(!err11.err)

	// assert keys equal.
	primitive.Assert(isReg)
	primitive.Assert(std.BytesEqual(pk0, pk1))
}
