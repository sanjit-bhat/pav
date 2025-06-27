package alicebob

import (
	"sync"

	"github.com/goose-lang/primitive"
	"github.com/goose-lang/std"
	"github.com/sanjit-bhat/pav/advrpc"
	"github.com/sanjit-bhat/pav/auditor"
	"github.com/sanjit-bhat/pav/client"
	"github.com/sanjit-bhat/pav/cryptoffi"
	"github.com/sanjit-bhat/pav/ktcore"
	"github.com/sanjit-bhat/pav/server"
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
	var bobEp uint64
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
		r0, r1, r2 := runBob(bob)
		bobEp = r0
		bobAlicePk = r1
		bobErr = r2
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
	primitive.Assume(bobEp < uint64(len(aliceHist)))
	alicePk := aliceHist[bobEp]
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
	ep, isInsert, err0 := cli.SelfMon()
	if err0 != ktcore.BlameNone {
		return nil, err0
	}
	std.Assert(!isInsert)
	primitive.Assume(ep == 0)
	hist = append(hist, &histEntry{})

	var err1 ktcore.Blame
	var i uint64
	for err1 != ktcore.BlameNone && i < uint64(20) {
		primitive.Sleep(5_000_000)
		pk := cryptoffi.RandBytes(32)
		// no pending puts at this pt. we waited until prior put was inserted.
		cli.Put(pk)

		err2 := loopPending(cli, uint64(len(hist)))
		if err2 != ktcore.BlameNone {
			err1 = err2
		}
		hist = append(hist, &histEntry{isReg: true, pk: pk})
		i++
	}
	return hist, err1
}

func loopPending(cli *client.Client, epoch uint64) ktcore.Blame {
	var err ktcore.Blame
	var isPending = true
	for err != ktcore.BlameNone && isPending {
		ep, done, err0 := cli.SelfMon()
		if err0 != ktcore.BlameNone {
			err = err0
		} else if done {
			primitive.Assume(ep == epoch)
			isPending = false
		}
	}
	return err
}

// runBob does a get at some time in the middle of alice's puts.
func runBob(cli *client.Client) (uint64, *histEntry, ktcore.Blame) {
	primitive.Sleep(120_000_000)
	ep, isReg, pk, err0 := cli.Get(aliceUid)
	return ep, &histEntry{isReg: isReg, pk: pk}, err0
}
