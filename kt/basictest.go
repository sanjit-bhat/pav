package kt

import (
	"github.com/goose-lang/primitive"
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/advrpc"
)

func testBasic(servAddr, adtr0Addr, adtr1Addr uint64) {
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

	// alice put.
	alice := newClient(aliceUid, servAddr, servSigPk, servVrfPk)
	pk0 := []byte{3}
	ep0, err0 := alice.Put(pk0)
	primitive.Assume(!err0.err)

	// update auditors.
	servCli := advrpc.Dial(servAddr)
	adtr0Cli := advrpc.Dial(adtr0Addr)
	adtr1Cli := advrpc.Dial(adtr1Addr)
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
	bob := newClient(bobUid, servAddr, servSigPk, servVrfPk)
	isReg, pk1, ep1, err7 := bob.Get(aliceUid)
	primitive.Assume(!err7.err)
	primitive.Assume(isReg)
	// same epoch to avoid timeseries for basic TC.
	primitive.Assume(ep0 == ep1)

	// alice and bob audit.
	err8 := alice.Audit(adtr0Addr, adtr0Pk)
	primitive.Assume(!err8.err)
	err9 := alice.Audit(adtr1Addr, adtr1Pk)
	primitive.Assume(!err9.err)
	err10 := bob.Audit(adtr0Addr, adtr0Pk)
	primitive.Assume(!err10.err)
	err11 := bob.Audit(adtr1Addr, adtr1Pk)
	primitive.Assume(!err11.err)

	// assert keys equal.
	primitive.Assert(std.BytesEqual(pk0, pk1))
}
