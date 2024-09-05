package kt

import (
	"github.com/goose-lang/goose/machine"
	"github.com/goose-lang/std"
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/merkle"
)

func testAgreement(servAddr, adtr0Addr, adtr1Addr grove_ffi.Address) {
	// Start server and two auditors.
	serv, servPk := newServer()
	helpers := &helpersTy{servPk: servPk}
	go func() {
		serv.start(servAddr)
	}()
	adtr0, adtr0Pk := newAuditor(servPk)
	adtr1, adtr1Pk := newAuditor(servPk)
	go func() {
		adtr0.start(adtr0Addr)
	}()
	go func() {
		adtr1.start(adtr1Addr)
	}()
	machine.Sleep(1_000_000)
	servCli := urpc.MakeClient(servAddr)
	adtr0Cli := urpc.MakeClient(adtr0Addr)
	adtr1Cli := urpc.MakeClient(adtr1Addr)

	// Alice puts key.
	aliceId := cryptoffi.Hash([]byte("alice"))
	aliceCli := newClient(aliceId, servAddr, servPk)
	aliceKey0 := []byte("key")
	putEp := helpers.put(aliceCli, aliceKey0)

	// Update server / auditors.
	callServUpdateEpoch(servCli)
	updateAdtr(servCli, adtr0Cli, 2)
	updateAdtr(servCli, adtr1Cli, 2)

	// Alice does checks.
	helpers.selfCheckThru(aliceCli, putEp)
	helpers.auditThru(aliceCli, adtr0Addr, adtr0Pk, putEp)
	helpers.auditThru(aliceCli, adtr1Addr, adtr1Pk, putEp)

	// Bob gets Alice's key and does checks.
	bobId := cryptoffi.Hash([]byte("bob"))
	bobCli := newClient(bobId, servAddr, servPk)
	aliceKey1 := helpers.getAt(bobCli, aliceId, putEp)
	helpers.auditThru(bobCli, adtr0Addr, adtr0Pk, putEp)
	helpers.auditThru(bobCli, adtr1Addr, adtr1Pk, putEp)

	// Final assert. Bob got the same key Alice put.
	machine.Assert(std.BytesEqual(aliceKey0, aliceKey1))
}

type helpersTy struct {
	servPk cryptoffi.PublicKey
}

func (h *helpersTy) put(c *client, val merkle.Val) epochTy {
	putEp, evidAlLink0, err0 := c.put(val)
	if evidAlLink0 != nil {
		err := evidAlLink0.check(h.servPk)
		machine.Assert(!err)
		// TODO: machine.Exit whenever we have evidence.
	} else {
		machine.Assume(!err0)
	}
	return putEp
}

func updateAdtr(servCli, adtrCli *urpc.Client, numEpochs uint64) {
	for i := uint64(0); i < numEpochs; i++ {
		reply := callServGetLink(servCli, i)
		machine.Assume(!reply.error)
		err := callAdtrPut(adtrCli, reply.prevLink, reply.dig, reply.sig)
		machine.Assume(!err)
	}
}

func (h *helpersTy) selfCheckThru(c *client, thru epochTy) {
	selfEp, evidLink, evidAlPut, err0 := c.selfCheck()
	if evidLink != nil {
		err := evidLink.check(h.servPk)
		machine.Assert(!err)
	} else if evidAlPut != nil {
		err := evidAlPut.check(h.servPk)
		machine.Assert(!err)
	} else {
		machine.Assume(!err0)
	}
	machine.Assume(thru < selfEp)
}

func (h *helpersTy) auditThru(c *client, adtrAddr grove_ffi.Address, adtrPk cryptoffi.PublicKey, thru epochTy) {
	auditEp, evidLink, err0 := c.audit(adtrAddr, adtrPk)
	if evidLink != nil {
		err := evidLink.check(h.servPk)
		machine.Assert(!err)
	} else {
		machine.Assume(!err0)
	}
	machine.Assume(thru < auditEp)
}

func (h *helpersTy) getAt(c *client, id merkle.Id, epoch epochTy) merkle.Val {
	retVal, evidLink, err0 := c.getAt(id, epoch)
	if evidLink != nil {
		err := evidLink.check(h.servPk)
		machine.Assert(!err)
	} else {
		machine.Assume(!err0)
	}
	return retVal
}
