package alicebob

import (
	"bytes"
	"sync"
	"time"

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
	aliceUid uint64 = iota
	bobUid
)

func init() {
	server.BatchTimeout = time.Millisecond
}

func testAliceBob(servAddr uint64, adtrAddr uint64) (evid *client.Evid, err ktcore.Blame) {
	// setup server and auditor.
	serv, servSigPk := server.New()
	servRpc := server.NewRpcServer(serv)
	servRpc.Serve(servAddr)
	time.Sleep(time.Millisecond)

	// TODO: a more complete example has multiple auditors that each
	// check a segment of the full epoch hist.
	adtr, adtrPk, err := auditor.New(servAddr, servSigPk)
	if err != ktcore.BlameNone {
		return
	}
	adtrRpc := auditor.NewRpcAuditor(adtr)
	adtrRpc.Serve(adtrAddr)
	time.Sleep(time.Millisecond)

	// setup alice and bob.
	alice, err := client.New(aliceUid, servAddr, servSigPk)
	if err != ktcore.BlameNone {
		return
	}
	bob, err := client.New(bobUid, servAddr, servSigPk)
	if err != ktcore.BlameNone {
		return
	}

	// run first audit to learn auditor has init epoch in its hist.
	if evid, err = alice.Audit(adtrAddr, adtrPk); err != ktcore.BlameNone {
		return
	}
	if evid, err = bob.Audit(adtrAddr, adtrPk); err != ktcore.BlameNone {
		return
	}

	// run alice and bob.
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
		err = aliceErr
		return
	}
	if bobErr != ktcore.BlameNone {
		err = bobErr
		return
	}

	// sync auditor and do second audit.
	// in real world, this'll happen periodically.
	adtrCli := advrpc.Dial(adtrAddr)
	if err = auditor.CallUpdate(adtrCli); err != ktcore.BlameNone {
		return
	}
	if evid, err = alice.Audit(adtrAddr, adtrPk); err != ktcore.BlameNone {
		return
	}
	if evid, err = bob.Audit(adtrAddr, adtrPk); err != ktcore.BlameNone {
		return
	}

	// final check. bob got the right key.
	// Assume alice monitored bob's Get epoch.
	primitive.Assume(bobEp < uint64(len(aliceHist)))
	alicePk := aliceHist[bobEp]
	if !equal(alicePk, bobAlicePk) {
		// [ktcore.BlameServSig] works equally well.
		// both assumptions specify correct auditing.
		err = ktcore.BlameAdtrSig
		return
	}
	return
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
		return bytes.Equal(o0.pk, o1.pk)
	}
	return true
}

// runAlice does a bunch of puts.
func runAlice(cli *client.Client) (hist []*histEntry, err ktcore.Blame) {
	// in this simple example, alice is the only putter.
	// she can Assume that epochs update iff her Put executes,
	// which leads to a simple history structure.
	{
		var ep uint64
		var isInsert bool
		ep, isInsert, err = cli.SelfMon()
		if err != ktcore.BlameNone {
			return
		}
		std.Assert(!isInsert)
		primitive.Assume(ep == 0)
		hist = append(hist, &histEntry{})
	}

	for i := 0; i < 20; i++ {
		time.Sleep(5 * time.Millisecond)
		pk := cryptoffi.RandBytes(32)
		// no pending puts at this pt. we waited until prior put was inserted.
		cli.Put(pk)

		if err = loopPending(cli, uint64(len(hist))); err != ktcore.BlameNone {
			return
		}
		hist = append(hist, &histEntry{isReg: true, pk: pk})
	}
	return
}

func loopPending(cli *client.Client, ep uint64) (err ktcore.Blame) {
	for {
		var ep0 uint64
		var done bool
		ep0, done, err = cli.SelfMon()
		if err != ktcore.BlameNone {
			return
		}
		if done {
			primitive.Assume(ep0 == ep)
			break
		}
	}
	return
}

// runBob does a get at some time in the middle of alice's puts.
func runBob(cli *client.Client) (ep uint64, ent *histEntry, err ktcore.Blame) {
	time.Sleep(120 * time.Millisecond)
	ep, isReg, pk, err := cli.Get(aliceUid)
	ent = &histEntry{isReg: isReg, pk: pk}
	return
}
