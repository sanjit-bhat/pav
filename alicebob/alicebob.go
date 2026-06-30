package alicebob

import (
	"bytes"
	"time"

	"github.com/goose-lang/primitive"
	"github.com/goose-lang/std"
	"github.com/sanjit-bhat/pav/auditor"
	"github.com/sanjit-bhat/pav/client"
	"github.com/sanjit-bhat/pav/cryptoffi"
	"github.com/sanjit-bhat/pav/ktcore"
	"github.com/sanjit-bhat/pav/server"
)

const (
	aliceUid uint64 = iota
	bobUid
	epochTime = time.Millisecond
)

func testAliceBob(servAddr uint64, servGood bool, adtrAddrs []uint64) {
	serv, servPk := server.New(epochTime)
	server.NewRpcServer(serv).Serve(servAddr)
	time.Sleep(time.Millisecond)

	// epoch 0.
	alice, ep, err := client.New(aliceUid, servAddr, servPk)
	primitive.Assume(err == ktcore.BlameNone)
	primitive.Assume(ep == 0)
	bob, ep, err := client.New(bobUid, servAddr, servPk)
	primitive.Assume(err == ktcore.BlameNone)
	primitive.Assume(ep == 0)
	ep, bobHasPk0, _, err := bob.Get(aliceUid)
	primitive.Assume(err == ktcore.BlameNone)
	primitive.Assume(ep == 0)

	var adtr0, adtr1 *auditor.Auditor
	var adtr0Pk, adtr1Pk []byte
	if !servGood {
		adtr0, adtr0Pk, err = auditor.New(servAddr, servPk)
		primitive.Assume(err == ktcore.BlameNone)
		adtr1, adtr1Pk, err = auditor.New(servAddr, servPk)
		primitive.Assume(err == ktcore.BlameNone)
		auditor.NewRpcAuditor(adtr0).Serve(adtrAddrs[0])
		auditor.NewRpcAuditor(adtr1).Serve(adtrAddrs[1])
		time.Sleep(time.Millisecond)
	}

	// epoch 1.
	alicePk1 := cryptoffi.RandBytes(32)
	alice.Put(alicePk1)
	time.Sleep(2 * epochTime)
	ep, isChanged, err := alice.SelfMon()
	primitive.Assume(err == ktcore.BlameNone)
	primitive.Assume(ep == 1)
	primitive.Assume(isChanged)
	ep, bobHasPk1, bobPk1, err := bob.Get(aliceUid)
	primitive.Assume(err == ktcore.BlameNone)
	primitive.Assume(ep == 1)

	if !servGood {
		adtr0.Update()
		adtr1.Update()
		var startEp uint64
		startEp, ep, err, _ = alice.Audit(adtrAddrs[0], adtr0Pk)
		primitive.Assume(err == ktcore.BlameNone)
		primitive.Assume(startEp == 0)
		primitive.Assume(ep == 1)
		startEp, ep, err, _ = bob.Audit(adtrAddrs[1], adtr1Pk)
		primitive.Assume(err == ktcore.BlameNone)
		primitive.Assume(startEp == 0)
		primitive.Assume(ep == 1)
	}

	var adtr2 *auditor.Auditor
	var adtr2Pk []byte
	if !servGood {
		adtr2, adtr2Pk, err = auditor.New(servAddr, servPk)
		primitive.Assume(err == ktcore.BlameNone)
		auditor.NewRpcAuditor(adtr2).Serve(adtrAddrs[2])
		time.Sleep(time.Millisecond)
	}

	// epoch 2.
	alicePk2 := cryptoffi.RandBytes(32)
	alice.Put(alicePk2)
	time.Sleep(2 * epochTime)
	ep, isChanged, err = alice.SelfMon()
	primitive.Assume(err == ktcore.BlameNone)
	primitive.Assume(ep == 2)
	primitive.Assume(isChanged)
	ep, bobHasPk2, bobPk2, err := bob.Get(aliceUid)
	primitive.Assume(err == ktcore.BlameNone)
	primitive.Assume(ep == 2)

	if !servGood {
		adtr2.Update()
		var startEp uint64
		startEp, ep, err, _ = alice.Audit(adtrAddrs[2], adtr2Pk)
		primitive.Assume(err == ktcore.BlameNone)
		primitive.Assume(startEp == 1)
		primitive.Assume(ep == 2)
		startEp, ep, err, _ = bob.Audit(adtrAddrs[2], adtr2Pk)
		primitive.Assume(err == ktcore.BlameNone)
		primitive.Assume(startEp == 1)
		primitive.Assume(ep == 2)
	}

	// "KT consistency".
	std.Assert(!bobHasPk0)
	std.Assert(bobHasPk1)
	std.Assert(bytes.Equal(bobPk1, alicePk1))
	std.Assert(bobHasPk2)
	std.Assert(bytes.Equal(bobPk2, alicePk2))
}
