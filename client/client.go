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
	last, errb := c.getChainExt(chainProof, sig)
	if errb {
		err = ktcore.BlameServFull
		return
	}
	if checkHist(c.serv.vrfPk, uid, 0, last.dig, hist) {
		err = ktcore.BlameServFull
		return
	}
	boundVer := uint64(len(hist))
	if checkNonMemb(c.serv.vrfPk, uid, boundVer, last.dig, bound) {
		err = ktcore.BlameServFull
		return
	}

	// update.
	c.last = last
	if boundVer == 0 {
		return last.epoch, false, nil, ktcore.BlameNone
	} else {
		lastKey := hist[boundVer-1]
		return last.epoch, true, lastKey.PkOpen.Val, ktcore.BlameNone
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
	last, errb := c.getChainExt(chainProof, sig)
	if errb {
		err = ktcore.BlameServFull
		return
	}
	if checkHist(c.serv.vrfPk, c.uid, c.pend.ver, last.dig, hist) {
		err = ktcore.BlameServFull
		return
	}
	histLen := uint64(len(hist))
	boundVer := c.pend.ver + histLen
	if checkNonMemb(c.serv.vrfPk, c.uid, boundVer, last.dig, bound) {
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
		c.last = last
		return last.epoch, false, ktcore.BlameNone
	}
	// good client only has one version update at a time.
	if histLen > 1 {
		err = ktcore.BlameServFull | ktcore.BlameClients
		return
	}
	// update hasn't yet fired.
	if histLen == 0 {
		c.last = last
		return last.epoch, false, ktcore.BlameNone
	}
	newKey := hist[0]
	// equals pending put.
	if !bytes.Equal(newKey.PkOpen.Val, c.pend.pendingPk) {
		err = ktcore.BlameServFull | ktcore.BlameClients
		return
	}

	// update.
	c.last = last
	c.pend.isPending = false
	c.pend.pendingPk = nil
	// this client controls nextVer, so no need to check for overflow.
	c.pend.ver = std.SumAssumeNoOverflow(c.pend.ver, 1)
	return last.epoch, true, ktcore.BlameNone
}

func (c *Client) Audit(adtrAddr uint64, adtrPk cryptoffi.SigPublicKey) (evid *Evid, err ktcore.Blame) {
	cli := advrpc.Dial(adtrAddr)
	last := c.last
	audit := auditor.CallGet(cli, last.epoch)
	if audit.Err != ktcore.BlameNone {
		err = audit.Err
		return
	}

	// check adtr sig for consistency under untrusted server and trusted auditor.
	// check serv sig to catch serv misbehavior.

	// vrf evidence.
	if ktcore.VerifyVrfSig(adtrPk, audit.VrfPk, audit.AdtrVrfSig) {
		err = ktcore.BlameAdtrFull
		return
	}
	if ktcore.VerifyVrfSig(c.serv.sigPk, audit.VrfPk, audit.ServVrfSig) {
		err = ktcore.BlameAdtrFull
		return
	}
	vrfPkB := cryptoffi.VrfPublicKeyEncode(c.serv.vrfPk)
	if !bytes.Equal(vrfPkB, audit.VrfPk) {
		evid = &Evid{vrf: &evidVrf{vrfPk0: vrfPkB, sig0: c.serv.vrfSig, vrfPk1: audit.VrfPk, sig1: audit.ServVrfSig}}
		err = ktcore.BlameServSig
		return
	}

	// link evidence.
	if ktcore.VerifyLinkSig(adtrPk, last.epoch, audit.Link, audit.AdtrLinkSig) {
		err = ktcore.BlameAdtrFull
		return
	}
	if ktcore.VerifyLinkSig(c.serv.sigPk, last.epoch, audit.Link, audit.ServLinkSig) {
		err = ktcore.BlameAdtrFull
		return
	}
	if !bytes.Equal(last.link, audit.Link) {
		evid = &Evid{link: &evidLink{epoch: last.epoch, link0: last.link, sig0: last.sig, link1: audit.Link, sig1: audit.ServLinkSig}}
		err = ktcore.BlameServSig
		return
	}
	return
}

func New(uid, servAddr uint64, servPk cryptoffi.SigPublicKey) (c *Client, err ktcore.Blame) {
	cli := advrpc.Dial(servAddr)
	reply, err := server.CallStart(cli)
	if err != ktcore.BlameNone {
		return
	}
	if uint64(len(reply.StartLink)) != cryptoffi.HashLen {
		err = ktcore.BlameServFull
		return
	}
	extLen, newDig, newLink, errb := hashchain.Verify(reply.StartLink, reply.ChainProof)
	if errb {
		err = ktcore.BlameServFull
		return
	}
	// want a starting dig.
	if extLen == 0 {
		err = ktcore.BlameServFull
		return
	}
	if !std.SumNoOverflow(reply.StartEpochLen, extLen-1) {
		err = ktcore.BlameServFull
		return
	}
	lastEp := reply.StartEpochLen + extLen - 1
	if ktcore.VerifyLinkSig(servPk, lastEp, newLink, reply.LinkSig) {
		err = ktcore.BlameServFull
		return
	}
	vrfPk, errb := cryptoffi.VrfPublicKeyDecode(reply.VrfPk)
	if errb {
		err = ktcore.BlameServFull
		return
	}
	if ktcore.VerifyVrfSig(servPk, reply.VrfPk, reply.VrfSig) {
		err = ktcore.BlameServFull
		return
	}

	pendingPut := &nextVer{}
	last := &epoch{epoch: lastEp, dig: newDig, link: newLink, sig: reply.LinkSig}
	serv := &serv{cli: cli, sigPk: servPk, vrfPk: vrfPk, vrfSig: reply.VrfSig}
	c = &Client{uid: uid, pend: pendingPut, last: last, serv: serv}
	return
}

func (c *Client) getChainExt(chainProof, sig []byte) (ep *epoch, err bool) {
	extLen, newDig, newLink, err := hashchain.Verify(c.last.link, chainProof)
	if err {
		return
	}
	if extLen == 0 {
		ep = c.last
		return
	}
	if !std.SumNoOverflow(c.last.epoch, extLen) {
		err = true
		return
	}
	newEp := c.last.epoch + extLen
	if ktcore.VerifyLinkSig(c.serv.sigPk, newEp, newLink, sig) {
		err = true
		return
	}
	ep = &epoch{epoch: newEp, dig: newDig, link: newLink, sig: sig}
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
