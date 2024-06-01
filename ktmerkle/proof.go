package ktmerkle

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/tchajed/goose/machine"
)

func updateAdtrDigs(servCli, adtrCli *urpc.Client) epochTy {
	var epoch uint64 = 0
	for {
		dig, sig, err0 := callGetDigest(servCli, epoch)
		if err0 {
			break
		}
		err1 := callUpdate(adtrCli, epoch, dig, sig)
		if err1 {
			break
		}
		epoch++
	}
	return epoch
}

func testAgreement(servAddr, adtrAddr grove_ffi.Address) {
	servSk, servPk := cryptoffi.MakeKeys()
	go func() {
		s := newKeyServ(servSk)
		s.start(servAddr)
	}()

	adtrSk, adtrPk := cryptoffi.MakeKeys()
	adtrPks := []cryptoffi.PublicKey{adtrPk}
	adtrAddrs := []grove_ffi.Address{adtrAddr}
	go func() {
		a := newAuditor(adtrSk, servPk)
		a.start(adtrAddr)
	}()

	machine.Sleep(1_000_000)
	servCli := urpc.MakeClient(servAddr)
	adtrCli := urpc.MakeClient(adtrAddr)

	aliceId := cryptoffi.Hash([]byte("alice"))
	aliceVal := []byte("val")
	aliceCli := newKeyCli(aliceId, servAddr, adtrAddrs, adtrPks, servPk)
	_, err0 := aliceCli.put(aliceVal)
	machine.Assume(!err0)

	emptyReplyB := make([]byte, 0)
	err1 := servCli.Call(rpcKeyServUpdateEpoch, nil, &emptyReplyB, 100)
	machine.Assume(err1 == urpc.ErrNone)

	epochAdtr := updateAdtrDigs(servCli, adtrCli)
	machine.Assume(epochAdtr == uint64(2))

	bobId := cryptoffi.Hash([]byte("bob"))
	bobCli := newKeyCli(bobId, servAddr, adtrAddrs, adtrPks, servPk)
	charlieId := cryptoffi.Hash([]byte("charlie"))
	charlieCli := newKeyCli(charlieId, servAddr, adtrAddrs, adtrPks, servPk)

	epoch0, val0, err3 := bobCli.get(aliceId)
	machine.Assume(!err3)
	epoch1, val1, err4 := charlieCli.get(aliceId)
	machine.Assume(!err4)

	epoch2, err5 := bobCli.audit(0)
	machine.Assume(!err5)
	epoch3, err6 := charlieCli.audit(0)
	machine.Assume(!err6)

	machine.Assume(epoch0 == epoch1)
	machine.Assume(epoch0 < epoch2)
	machine.Assume(epoch1 < epoch3)

	machine.Assert(std.BytesEqual(val0, val1))
}
