package alicebob

import (
	"bytes"
	"sync"
	"time"

	"github.com/goose-lang/primitive"
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
	server.EpochTime = time.Millisecond
}

func testAliceBob(servAddr uint64, adtrAddr uint64) (err ktcore.Blame, evid *ktcore.Evid) {
	// setup server and auditor.
	serv, servSigPk := server.New()
	servRpc := server.NewRpcServer(serv)
	servRpc.Serve(servAddr)
	time.Sleep(time.Millisecond)

	// TODO: example stitching multiple auditors together.
	// TODO: example with just good server and no auditors.
	adtr, adtrPk, err := auditor.New(servAddr, servSigPk)
	if err != ktcore.BlameNone {
		return
	}
	adtrRpc := auditor.NewRpcAuditor(adtr)
	adtrRpc.Serve(adtrAddr)
	time.Sleep(time.Millisecond)

	// setup alice and bob.
	alice, aliceStartEp, err := client.New(aliceUid, servAddr, servSigPk)
	if err != ktcore.BlameNone {
		return
	}
	primitive.Assume(aliceStartEp == 0)
	bob, _, err := client.New(bobUid, servAddr, servSigPk)
	if err != ktcore.BlameNone {
		return
	}

	// run alice and bob.
	var aliceHist []*optPk
	var aliceErr ktcore.Blame
	var bobEp uint64
	var bobAlicePk *optPk
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
	// in real world, sync will happen periodically.
	if err = adtr.Update(); err != ktcore.BlameNone {
		return
	}
	adtrStartEp0, _, err, evid := alice.Audit(adtrAddr, adtrPk)
	if err != ktcore.BlameNone {
		return
	}
	primitive.Assume(adtrStartEp0 == 0)
	adtrStartEp1, _, err, evid := bob.Audit(adtrAddr, adtrPk)
	if err != ktcore.BlameNone {
		return
	}
	primitive.Assume(adtrStartEp1 == 0)

	// Assume alice monitored bob's Get epoch.
	primitive.Assume(bobEp < uint64(len(aliceHist)))
	alicePk := aliceHist[bobEp]
	// "KT consistency". in this test case, it means bob got the right key.
	if !equal(alicePk, bobAlicePk) {
		// at min, this property relies on auditor maintaining its sigpred.
		// or with no auditor, server maintaining its sigpred.
		err = ktcore.BlameAdtrSig
		return
	}
	return
}

type optPk struct {
	opt bool
	pk  []byte
}

func equal(o0, o1 *optPk) bool {
	if o0.opt != o1.opt {
		return false
	}
	if !o0.opt {
		return true
	}
	return bytes.Equal(o0.pk, o1.pk)
}

// runAlice does a bunch of puts.
func runAlice(cli *client.Client) (hist []*optPk, err ktcore.Blame) {
	// in this simple example, alice is the only putter.
	// she can assume that epochs update iff her Put executes,
	// which leads to a simple history structure.
	// from Client.New, know epoch 0.
	hist = append(hist, &optPk{})
	for i := 0; i < 20; i++ {
		time.Sleep(5 * time.Millisecond)
		pk := cryptoffi.RandBytes(32)
		// no pending puts at this pt. we waited until prior put was inserted.
		cli.Put(pk)

		if err = loopChanged(cli, uint64(len(hist))); err != ktcore.BlameNone {
			return
		}
		hist = append(hist, &optPk{opt: true, pk: pk})
	}
	return
}

func loopChanged(cli *client.Client, ep uint64) (err ktcore.Blame) {
	for {
		var ep0 uint64
		var isChanged bool
		ep0, isChanged, err = cli.SelfMon()
		if err != ktcore.BlameNone {
			return
		}
		if isChanged {
			primitive.Assume(ep0 == ep)
			break
		}
	}
	return
}

// runBob does a get at some time in the middle of alice's puts.
func runBob(cli *client.Client) (ep uint64, ent *optPk, err ktcore.Blame) {
	time.Sleep(120 * time.Millisecond)
	ep, isReg, pk, err := cli.Get(aliceUid)
	ent = &optPk{opt: isReg, pk: pk}
	return
}
