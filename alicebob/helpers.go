package alicebob

import (
	"github.com/goose-lang/primitive"
	"github.com/mit-pdos/pav/advrpc"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/kt"
)

type setupParams struct {
	servAddr  uint64
	servSigPk cryptoffi.SigPublicKey
	servVrfPk []byte
	adtrAddrs []uint64
	adtrPks   []cryptoffi.SigPublicKey
}

// setup starts server and auditors. it's mainly a logical convenience.
// it consolidates the external parties, letting us more easily describe
// different adversary configs.
func setup(servAddr uint64, adtrAddrs []uint64) *setupParams {
	serv, servSigPk, servVrfPk := kt.NewServer()
	servVrfPkEnc := cryptoffi.VrfPublicKeyEncode(servVrfPk)
	servRpc := kt.NewRpcServer(serv)
	servRpc.Serve(servAddr)
	var adtrPks []cryptoffi.SigPublicKey
	for _, adtrAddr := range adtrAddrs {
		adtr, adtrPk := kt.NewAuditor()
		adtrRpc := kt.NewRpcAuditor(adtr)
		adtrRpc.Serve(adtrAddr)
		adtrPks = append(adtrPks, adtrPk)
	}
	primitive.Sleep(1_000_000)
	return &setupParams{servAddr: servAddr, servSigPk: servSigPk, servVrfPk: servVrfPkEnc, adtrAddrs: adtrAddrs, adtrPks: adtrPks}
}

func mkRpcClients(addrs []uint64) []*advrpc.Client {
	var c []*advrpc.Client
	for _, addr := range addrs {
		cli := advrpc.Dial(addr)
		c = append(c, cli)
	}
	return c
}

func updAdtrsOnce(upd *kt.UpdateProof, adtrs []*advrpc.Client) {
	for _, cli := range adtrs {
		err := kt.CallAdtrUpdate(cli, upd)
		primitive.Assume(!err)
	}
}

func doAudits(cli *kt.Client, adtrAddrs []uint64, adtrPks []cryptoffi.SigPublicKey) {
	numAdtrs := uint64(len(adtrAddrs))
	for i := uint64(0); i < numAdtrs; i++ {
		addr := adtrAddrs[i]
		pk := adtrPks[i]
		err := cli.Audit(addr, pk)
		primitive.Assume(!err.Err)
	}
}

func updAdtrsAll(servAddr uint64, adtrAddrs []uint64) {
	servCli := advrpc.Dial(servAddr)
	adtrs := mkRpcClients(adtrAddrs)
	var epoch uint64
	for {
		upd, err := kt.CallServAudit(servCli, epoch)
		if err {
			break
		}
		updAdtrsOnce(upd, adtrs)
		epoch++
	}
}
