package client

import (
	"bytes"

	"github.com/goose-lang/std"
	"github.com/sanjit-bhat/pav/advrpc"
	"github.com/sanjit-bhat/pav/auditor"
	"github.com/sanjit-bhat/pav/cryptoffi"
	"github.com/sanjit-bhat/pav/hashchain"
	"github.com/sanjit-bhat/pav/ktcore"
	"github.com/sanjit-bhat/pav/merkle"
	"github.com/sanjit-bhat/pav/server"
)

type Client struct {
	uid  uint64
	pend *nextVer
	last *epoch
	serv *serv
}

type nextVer struct {
	ver       uint64
	isPending bool
	pendingPk []byte
}

type epoch struct {
	epoch uint64
	dig   []byte
	link  []byte
	sig   []byte
}

type serv struct {
	cli    *advrpc.Client
	sigPk  cryptoffi.SigPublicKey
	vrfPk  *cryptoffi.VrfPublicKey
	vrfSig []byte
}

// Put queues pk for insertion.
// if we have a pending Put, it requires the pk to be the same.
func (c *Client) Put(pk []byte) {
	if c.pend.isPending {
		std.Assert(bytes.Equal(c.pend.pendingPk, pk))
	} else {
		c.pend.isPending = true
		c.pend.pendingPk = pk
	}
	server.CallPut(c.serv.cli, c.uid, pk, c.pend.ver)
}

// Get a uid's pk.
func (c *Client) Get(uid uint64) (ep uint64, isReg bool, pk []byte, err ktcore.Blame) {
	chainProof, sig, hist, bound, err := server.CallHistory(c.serv.cli, uid, c.last.epoch, 0)
	if err != ktcore.BlameNone {
		return
	}
	// check.
	next, errb := getNextEp(c.last, c.serv.sigPk, chainProof, sig)
	if errb {
		err = ktcore.BlameServFull
		return
	}
	if checkHist(c.serv.vrfPk, uid, 0, next.dig, hist) {
		err = ktcore.BlameServFull
		return
	}
	boundVer := uint64(len(hist))
	if checkNonMemb(c.serv.vrfPk, uid, boundVer, next.dig, bound) {
		err = ktcore.BlameServFull
		return
	}

	// update.
	c.last = next
	if boundVer == 0 {
		return next.epoch, false, nil, ktcore.BlameNone
	} else {
		lastKey := hist[boundVer-1]
		return next.epoch, true, lastKey.PkOpen.Val, ktcore.BlameNone
	}
}

// SelfMon a client's own uid.
// if isChanged, the key was added sometime from the last SelfMon.
func (c *Client) SelfMon() (ep uint64, isChanged bool, err ktcore.Blame) {
	chainProof, sig, hist, bound, err := server.CallHistory(c.serv.cli, c.uid, c.last.epoch, c.pend.ver)
	if err != ktcore.BlameNone {
		return
	}
	// check.
	next, errb := getNextEp(c.last, c.serv.sigPk, chainProof, sig)
	if errb {
		err = ktcore.BlameServFull
		return
	}
	histLen := uint64(len(hist))
	boundVer := c.pend.ver + histLen
	if !std.SumNoOverflow(c.pend.ver, histLen) {
		err = ktcore.BlameServFull
		return
	}
	if checkHist(c.serv.vrfPk, c.uid, c.pend.ver, next.dig, hist) {
		err = ktcore.BlameServFull
		return
	}
	if checkNonMemb(c.serv.vrfPk, c.uid, boundVer, next.dig, bound) {
		err = ktcore.BlameServFull
		return
	}

	// check consistency with pending.
	if !c.pend.isPending {
		// if no pending, shouldn't have any updates.
		if histLen != 0 {
			// conflicting updates could also come from other bad clients.
			err = ktcore.BlameServFull | ktcore.BlameClients
			return
		}
		c.last = next
		return next.epoch, false, ktcore.BlameNone
	}
	// good client only has one version update at a time.
	if histLen > 1 {
		err = ktcore.BlameServFull | ktcore.BlameClients
		return
	}
	// update hasn't yet fired.
	if histLen == 0 {
		c.last = next
		return next.epoch, false, ktcore.BlameNone
	}
	newKey := hist[0]
	// equals pending put.
	if !bytes.Equal(newKey.PkOpen.Val, c.pend.pendingPk) {
		err = ktcore.BlameServFull | ktcore.BlameClients
		return
	}

	// update.
	c.last = next
	c.pend.isPending = false
	c.pend.pendingPk = nil
	c.pend.ver = boundVer
	return next.epoch, true, ktcore.BlameNone
}

func (c *Client) Audit(adtrAddr uint64, adtrPk cryptoffi.SigPublicKey) (evid *Evid, err ktcore.Blame) {
	cli := advrpc.Dial(adtrAddr)
	last := c.last
	link, vrf, err := auditor.CallGet(cli, last.epoch)
	if err != ktcore.BlameNone {
		return
	}
	// check adtr sig for consistency under untrusted server and trusted auditor.
	// check serv sig to catch serv misbehavior.
	if checkAuditLink(c.serv.sigPk, adtrPk, last.epoch, link) {
		err = ktcore.BlameAdtrFull
		return
	}
	if checkAuditVrf(c.serv.sigPk, adtrPk, vrf) {
		err = ktcore.BlameAdtrFull
		return
	}

	// vrf evidence.
	vrfPkB := cryptoffi.VrfPublicKeyEncode(c.serv.vrfPk)
	if !bytes.Equal(vrfPkB, vrf.VrfPk) {
		evid = &Evid{vrf: &evidVrf{vrfPk0: vrfPkB, sig0: c.serv.vrfSig, vrfPk1: vrf.VrfPk, sig1: vrf.ServSig}}
		err = ktcore.BlameServSig
		return
	}
	// link evidence.
	if !bytes.Equal(last.link, link.Link) {
		evid = &Evid{link: &evidLink{epoch: last.epoch, link0: last.link, sig0: last.sig, link1: link.Link, sig1: link.ServSig}}
		err = ktcore.BlameServSig
		return
	}
	return
}

func New(uid, servAddr uint64, servPk cryptoffi.SigPublicKey) (c *Client, err ktcore.Blame) {
	cli := advrpc.Dial(servAddr)
	chain, vrf, err := server.CallStart(cli)
	if err != ktcore.BlameNone {
		return
	}
	startEp, startDig, startLink, errb := auditor.CheckStartChain(servPk, chain)
	if errb {
		err = ktcore.BlameServFull
		return
	}
	vrfPk, errb := auditor.CheckStartVrf(servPk, vrf)
	if errb {
		err = ktcore.BlameServFull
		return
	}

	pendingPut := &nextVer{}
	last := &epoch{epoch: startEp, dig: startDig, link: startLink, sig: chain.LinkSig}
	serv := &serv{cli: cli, sigPk: servPk, vrfPk: vrfPk, vrfSig: vrf.VrfSig}
	c = &Client{uid: uid, pend: pendingPut, last: last, serv: serv}
	return
}

func getNextEp(prev *epoch, sigPk cryptoffi.SigPublicKey, chainProof, sig []byte) (next *epoch, err bool) {
	extLen, newDig, newLink, err := hashchain.Verify(prev.link, chainProof)
	if err {
		return
	}
	if extLen == 0 {
		next = prev
		return
	}
	newEp := prev.epoch + extLen
	if !std.SumNoOverflow(prev.epoch, extLen) {
		err = true
		return
	}
	if ktcore.VerifyLinkSig(sigPk, newEp, newLink, sig) {
		err = true
		return
	}
	next = &epoch{epoch: newEp, dig: newDig, link: newLink, sig: sig}
	return
}

func checkMemb(vrfPk *cryptoffi.VrfPublicKey, uid, ver uint64, dig []byte, memb *ktcore.Memb) (err bool) {
	label, err := ktcore.CheckMapLabel(vrfPk, uid, ver, memb.LabelProof)
	if err {
		return
	}
	mapVal := ktcore.GetMapVal(memb.PkOpen)
	dig0, err := merkle.VerifyMemb(label, mapVal, memb.MerkleProof)
	if err {
		return
	}
	if !bytes.Equal(dig, dig0) {
		err = true
		return
	}
	return
}

func checkHist(vrfPk *cryptoffi.VrfPublicKey, uid, prefixLen uint64, dig []byte, hist []*ktcore.Memb) (err bool) {
	for ver, memb := range hist {
		if err = checkMemb(vrfPk, uid, prefixLen+uint64(ver), dig, memb); err {
			return
		}
	}
	return
}

func checkNonMemb(vrfPk *cryptoffi.VrfPublicKey, uid, ver uint64, dig []byte, nonMemb *ktcore.NonMemb) (err bool) {
	label, err := ktcore.CheckMapLabel(vrfPk, uid, ver, nonMemb.LabelProof)
	if err {
		return
	}
	dig0, err := merkle.VerifyNonMemb(label, nonMemb.MerkleProof)
	if err {
		return
	}
	if !bytes.Equal(dig, dig0) {
		err = true
		return
	}
	return
}

func checkAuditLink(servPk, adtrPk cryptoffi.SigPublicKey, ep uint64, link *auditor.SignedLink) (err bool) {
	if ktcore.VerifyLinkSig(adtrPk, ep, link.Link, link.AdtrSig) {
		return true
	}
	if ktcore.VerifyLinkSig(servPk, ep, link.Link, link.ServSig) {
		return true
	}
	return
}

func checkAuditVrf(servPk, adtrPk cryptoffi.SigPublicKey, vrf *auditor.SignedVrf) (err bool) {
	if ktcore.VerifyVrfSig(adtrPk, vrf.VrfPk, vrf.AdtrSig) {
		return true
	}
	if ktcore.VerifyVrfSig(servPk, vrf.VrfPk, vrf.ServSig) {
		return true
	}
	return
}
