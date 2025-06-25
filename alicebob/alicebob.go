package alicebob

import (
	"sync"

	"github.com/goose-lang/primitive"
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/advrpc"
	"github.com/mit-pdos/pav/auditor"
	"github.com/mit-pdos/pav/client"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/ktcore"
	"github.com/mit-pdos/pav/server"
)

const (
	aliceUid uint64 = 0
	bobUid   uint64 = 1
)

func testAliceBob(servAddr uint64, adtrAddr uint64) *client.ClientErr {
	// setup server and auditor.
	serv, servSigPk := server.New()
	servRpc := server.NewRpcServer(serv)
	servRpc.Serve(servAddr)
	primitive.Sleep(1_000_000)

	adtr, adtrPk, err0 := auditor.New(servAddr, servSigPk)
	if err0 != ktcore.BlameNone {
		return &client.ClientErr{Err: err0}
	}
	adtrRpc := auditor.NewRpcAuditor(adtr)
	adtrRpc.Serve(adtrAddr)
	primitive.Sleep(1_000_000)

	// start alice and bob.
	alice, err1 := client.New(aliceUid, servAddr, servSigPk)
	if err1 != ktcore.BlameNone {
		return &client.ClientErr{Err: err1}
	}
	bob, err2 := client.New(bobUid, servAddr, servSigPk)
	if err2 != ktcore.BlameNone {
		return &client.ClientErr{Err: err2}
	}
	var aliceHist []*histEntry
	var aliceErr ktcore.Blame
	var bobAlicePk *histEntry
	var bobErr ktcore.Blame

	wg := new(sync.WaitGroup)
	wg.Add(1)
	wg.Add(1)
	go func() {
		r0, r1 := runAlice(alice)
		aliceHist = r0
		aliceErr = r1
		wg.Done()
	}()
	go func() {
		r0, r1 := runBob(bob)
		bobAlicePk = r0
		bobErr = r1
		wg.Done()
	}()
	wg.Wait()

	if aliceErr != ktcore.BlameNone {
		return &client.ClientErr{Err: aliceErr}
	}
	if bobErr != ktcore.BlameNone {
		return &client.ClientErr{Err: bobErr}
	}

	// sync auditors and audit. in real world, this'll happen periodically.
	adtrCli := advrpc.Dial(adtrAddr)
	err3 := auditor.CallUpdate(adtrCli)
	if err3 != ktcore.BlameNone {
		return &client.ClientErr{Err: err3}
	}
	err4 := alice.Audit(adtrAddr, adtrPk)
	if err4.Err != ktcore.BlameNone {
		return err4
	}
	err5 := bob.Audit(adtrAddr, adtrPk)
	if err5.Err != ktcore.BlameNone {
		return err5
	}

	// final check. bob got the right key.
	// Assume alice monitored bob's Get epoch.
	primitive.Assume(bob.LastEpoch.Epoch <= alice.LastEpoch.Epoch)
	alicePk := aliceHist[bob.LastEpoch.Epoch]
	if !equal(alicePk, bobAlicePk) {
		// [ktcore.BlameServSig] works equally well.
		// both assumptions specify correct auditing.
		return &client.ClientErr{Err: ktcore.BlameAdtrSig}
	}
	return &client.ClientErr{}
}

type histEntry struct {
	isReg bool
	pk    []byte
}

func equal(o0, o1 *histEntry) bool {
	if o0.isReg != o1.isReg {
		return false
	}
	if o0.isReg {
		return std.BytesEqual(o0.pk, o1.pk)
	}
	return true
}

// runAlice does a bunch of puts.
func runAlice(cli *client.Client) ([]*histEntry, ktcore.Blame) {
	// in this simple example, alice is the only putter.
	// she can Assume that epochs update iff her Put executes,
	// which leads to a simple history structure.
	var hist []*histEntry
	{
		isInsert, err0 := cli.SelfMon()
		if err0 != ktcore.BlameNone {
			return nil, err0
		}
		std.Assert(!isInsert)
		primitive.Assume(cli.LastEpoch.Epoch == 0)
		hist = append(hist, &histEntry{})
	}

	for i := uint64(0); i < uint64(20); i++ {
		primitive.Sleep(5_000_000)
		pk := cryptoffi.RandBytes(32)
		// no pending puts at this pt. we waited until prior put was inserted.
		cli.Put(pk)

		var isPending = true
		for isPending {
			isInsert, err0 := cli.SelfMon()
			if err0 != ktcore.BlameNone {
				return nil, err0
			}
			if isInsert {
				primitive.Assume(cli.LastEpoch.Epoch == uint64(len(hist)))
				hist = append(hist, &histEntry{isReg: true, pk: pk})
				isPending = false
			}
		}
	}
	return hist, ktcore.BlameNone
}

// runBob does a get at some time in the middle of alice's puts.
func runBob(cli *client.Client) (*histEntry, ktcore.Blame) {
	primitive.Sleep(120_000_000)
	isReg, pk, err0 := cli.Get(aliceUid)
	return &histEntry{isReg: isReg, pk: pk}, err0
}
