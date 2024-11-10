package kt

import (
	"github.com/goose-lang/primitive"
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

// setup starts server and auditors. it's mainly a logical convenience.
// it consolidates the external parties, letting us more easily describe
// different adversary configs.
func setup(servAddr uint64, adtrAddrs []uint64) *setupParams {
	serv, servSigPk, servVrfPk := newServer()
	servRpc := newRpcServer(serv)
	servRpc.Serve(servAddr)
	var adtrPks []cryptoffi.PublicKey
	for _, adtrAddr := range adtrAddrs {
		adtr, adtrPk := newAuditor()
		adtrRpc := newRpcAuditor(adtr)
		adtrRpc.Serve(adtrAddr)
		adtrPks = append(adtrPks, adtrPk)
	}
	primitive.Sleep(1_000_000)
	return &setupParams{servAddr: servAddr, servSigPk: servSigPk, servVrfPk: servVrfPk, adtrAddrs: adtrAddrs, adtrPks: adtrPks}
}

func mkRpcClients(addrs []uint64) []*advrpc.Client {
	var c []*advrpc.Client
	for _, addr := range addrs {
		cli := advrpc.Dial(addr)
		c = append(c, cli)
	}
	return c
}

func updAdtrsOnce(upd *UpdateProof, adtrs []*advrpc.Client) {
	for _, cli := range adtrs {
		err := callAdtrUpdate(cli, upd)
		primitive.Assume(!err)
	}
}

func doAudits(cli *Client, adtrAddrs []uint64, adtrPks []cryptoffi.PublicKey) {
	numAdtrs := uint64(len(adtrAddrs))
	for i := uint64(0); i < numAdtrs; i++ {
		addr := adtrAddrs[i]
		pk := adtrPks[i]
		err := cli.Audit(addr, pk)
		primitive.Assume(!err.err)
	}
}

func updAdtrsAll(servAddr uint64, adtrAddrs []uint64) {
	servCli := advrpc.Dial(servAddr)
	adtrs := mkRpcClients(adtrAddrs)
	var epoch uint64
	for {
		upd, err := callServAudit(servCli, epoch)
		if err {
			break
		}
		updAdtrsOnce(upd, adtrs)
		epoch++
	}
}
