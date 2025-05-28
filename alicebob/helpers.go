package alicebob

import (
	"github.com/goose-lang/primitive"
	"github.com/mit-pdos/pav/advrpc"
	"github.com/mit-pdos/pav/auditor"
	"github.com/mit-pdos/pav/client"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/ktserde"
	"github.com/mit-pdos/pav/server"
)

func mkRpcClients(addrs []uint64) []*advrpc.Client {
	var c []*advrpc.Client
	for _, addr := range addrs {
		cli := advrpc.Dial(addr)
		c = append(c, cli)
	}
	return c
}

func doAudits(cli *client.Client, adtrAddrs []uint64, adtrPks []cryptoffi.SigPublicKey) {
	numAdtrs := uint64(len(adtrAddrs))
	for i := uint64(0); i < numAdtrs; i++ {
		addr := adtrAddrs[i]
		pk := adtrPks[i]
		err := cli.Audit(addr, pk)
		primitive.Assume(!err.Err)
	}
}

func updAdtrsOnce(upd *ktserde.UpdateProof, adtrs []*advrpc.Client) {
	for _, cli := range adtrs {
		err := auditor.CallAdtrUpdate(cli, upd)
		primitive.Assume(!err)
	}
}

func updAdtrsAll(servAddr uint64, adtrAddrs []uint64) {
	servCli := advrpc.Dial(servAddr)
	adtrs := mkRpcClients(adtrAddrs)
	var epoch uint64
	for {
		upd, err := server.CallServAudit(servCli, epoch)
		if err {
			break
		}
		updAdtrsOnce(upd, adtrs)
		epoch++
	}
}
