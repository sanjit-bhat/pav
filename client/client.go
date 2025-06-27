package client

import (
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
	pend *pending
	last *epoch
	serv *serv
}

type pending struct {
	nextVer   uint64
	isPending bool
	pk        []byte
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

// ClientErr abstracts errors that potentially have irrefutable evidence.
type ClientErr struct {
	Evid *Evid
	Err  ktcore.Blame
}

// Put queues pk for insertion.
// if we have a pending Put, it requires the pk to be the same.
func (c *Client) Put(pk []byte) {
	if c.pend.isPending {
		std.Assert(std.BytesEqual(c.pend.pk, pk))
	} else {
		c.pend.isPending = true
		c.pend.pk = pk
	}
	server.CallPut(c.serv.cli, c.uid, pk, c.pend.nextVer)
}

// Get returns the epoch, if the pk was registered, and the pk.
func (c *Client) Get(uid uint64) (uint64, bool, []byte, ktcore.Blame) {
	chainProof, sig, hist, bound, err0 := server.CallHistory(c.serv.cli, uid, c.last.epoch, 0)
	if err0 != ktcore.BlameNone {
		return 0, false, nil, err0
	}
	// check.
	last, err1 := c.getChainExt(chainProof, sig)
	if err1 {
		return 0, false, nil, ktcore.BlameServFull
	}
	if CheckHist(c.serv.vrfPk, uid, 0, last.dig, hist) {
		return 0, false, nil, ktcore.BlameServFull
	}
	boundVer := uint64(len(hist))
	if CheckNonMemb(c.serv.vrfPk, uid, boundVer, last.dig, bound) {
		return 0, false, nil, ktcore.BlameServFull
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

// SelfMon self-monitors a client's own uid in the latest epoch.
// it returns the epoch and if the key changed.
// the insertion happened sometime since the last SelfMon.
func (c *Client) SelfMon() (uint64, bool, ktcore.Blame) {
	chainProof, sig, hist, bound, err0 := server.CallHistory(c.serv.cli, c.uid, c.last.epoch, c.pend.nextVer)
	if err0 != ktcore.BlameNone {
		return 0, false, err0
	}
	// check.
	last, err1 := c.getChainExt(chainProof, sig)
	if err1 {
		return 0, false, ktcore.BlameServFull
	}
	if CheckHist(c.serv.vrfPk, c.uid, c.pend.nextVer, last.dig, hist) {
		return 0, false, ktcore.BlameServFull
	}
	histLen := uint64(len(hist))
	boundVer := c.pend.nextVer + histLen
	if CheckNonMemb(c.serv.vrfPk, c.uid, boundVer, last.dig, bound) {
		return 0, false, ktcore.BlameServFull
	}

	// check consistency with pending.
	if !c.pend.isPending {
		// if no pending, shouldn't have any updates.
		if histLen != 0 {
			// conflicting updates could also come from other bad clients.
			return 0, false, ktcore.BlameServFull | ktcore.BlameClients
		}
		c.last = last
		return last.epoch, false, ktcore.BlameNone
	}
	// good client only has one version update at a time.
	if histLen > 1 {
		return 0, false, ktcore.BlameServFull | ktcore.BlameClients
	}
	// update hasn't yet fired.
	if histLen == 0 {
		c.last = last
		return last.epoch, false, ktcore.BlameNone
	}
	newKey := hist[0]
	// equals pending put.
	if !std.BytesEqual(newKey.PkOpen.Val, c.pend.pk) {
		return 0, false, ktcore.BlameServFull | ktcore.BlameClients
	}

	// update.
	c.last = last
	c.pend.isPending = false
	c.pend.pk = nil
	// this client controls nextVer, so no need to check for overflow.
	c.pend.nextVer = std.SumAssumeNoOverflow(c.pend.nextVer, 1)
	return last.epoch, true, ktcore.BlameNone
}

func (c *Client) Audit(adtrAddr uint64, adtrPk cryptoffi.SigPublicKey) *ClientErr {
	cli := advrpc.Dial(adtrAddr)
	last := c.last
	audit := auditor.CallGet(cli, last.epoch)
	if audit.Err != ktcore.BlameNone {
		return &ClientErr{Err: audit.Err}
	}

	// check adtr sig for consistency under untrusted server and trusted auditor.
	// check serv sig to catch serv misbehavior.

	// vrf evidence.
	if ktcore.VerifyVrfSig(adtrPk, audit.VrfPk, audit.AdtrVrfSig) {
		return &ClientErr{Err: ktcore.BlameAdtrFull}
	}
	if ktcore.VerifyVrfSig(c.serv.sigPk, audit.VrfPk, audit.ServVrfSig) {
		return &ClientErr{Err: ktcore.BlameAdtrFull}
	}
	vrfPkB := cryptoffi.VrfPublicKeyEncode(c.serv.vrfPk)
	if !std.BytesEqual(vrfPkB, audit.VrfPk) {
		evid := &Evid{vrf: &evidVrf{vrfPk0: vrfPkB, sig0: c.serv.vrfSig, vrfPk1: audit.VrfPk, sig1: audit.ServVrfSig}}
		return &ClientErr{Evid: evid, Err: ktcore.BlameServSig}
	}

	// link evidence.
	if ktcore.VerifyLinkSig(adtrPk, last.epoch, audit.Link, audit.AdtrLinkSig) {
		return &ClientErr{Err: ktcore.BlameAdtrFull}
	}
	if ktcore.VerifyLinkSig(c.serv.sigPk, last.epoch, audit.Link, audit.ServLinkSig) {
		return &ClientErr{Err: ktcore.BlameAdtrFull}
	}
	if !std.BytesEqual(last.link, audit.Link) {
		evid := &Evid{link: &evidLink{epoch: last.epoch, link0: last.link, sig0: last.sig, link1: audit.Link, sig1: audit.ServLinkSig}}
		return &ClientErr{Evid: evid, Err: ktcore.BlameServSig}
	}
	return &ClientErr{Err: ktcore.BlameNone}
}

func New(uid, servAddr uint64, servPk cryptoffi.SigPublicKey) (*Client, ktcore.Blame) {
	cli := advrpc.Dial(servAddr)
	reply, err0 := server.CallStart(cli)
	if err0 != ktcore.BlameNone {
		return nil, err0
	}
	extLen, newDig, newLink, err1 := hashchain.Verify(reply.StartLink, reply.ChainProof)
	if err1 {
		return nil, ktcore.BlameServFull
	}
	// want a starting dig.
	if extLen == 0 {
		return nil, ktcore.BlameServFull
	}
	if !std.SumNoOverflow(reply.StartEpochLen, extLen-1) {
		return nil, ktcore.BlameServFull
	}
	lastEp := reply.StartEpochLen + extLen - 1
	if ktcore.VerifyLinkSig(servPk, lastEp, newLink, reply.LinkSig) {
		return nil, ktcore.BlameServFull
	}
	vrfPk, err2 := cryptoffi.VrfPublicKeyDecode(reply.VrfPk)
	if err2 {
		return nil, ktcore.BlameServFull
	}
	if ktcore.VerifyVrfSig(servPk, reply.VrfPk, reply.VrfSig) {
		return nil, ktcore.BlameServFull
	}

	pendingPut := &pending{}
	last := &epoch{epoch: lastEp, dig: newDig, link: newLink, sig: reply.LinkSig}
	serv := &serv{cli: cli, sigPk: servPk, vrfPk: vrfPk, vrfSig: reply.VrfSig}
	return &Client{uid: uid, pend: pendingPut, last: last, serv: serv}, ktcore.BlameNone
}

func (c *Client) getChainExt(chainProof, sig []byte) (*epoch, bool) {
	extLen, newDig, newLink, err0 := hashchain.Verify(c.last.link, chainProof)
	if err0 {
		return nil, true
	}
	if extLen == 0 {
		return c.last, false
	}
	if !std.SumNoOverflow(c.last.epoch, extLen) {
		return nil, true
	}
	newEp := c.last.epoch + extLen
	if ktcore.VerifyLinkSig(c.serv.sigPk, newEp, newLink, sig) {
		return nil, true
	}
	return &epoch{epoch: newEp, dig: newDig, link: newLink, sig: sig}, false
}

// CheckMemb errors on fail.
func CheckMemb(vrfPk *cryptoffi.VrfPublicKey, uid, ver uint64, dig []byte, memb *ktcore.Memb) bool {
	label, err0 := ktcore.CheckMapLabel(vrfPk, uid, ver, memb.LabelProof)
	if err0 {
		return true
	}
	mapVal := ktcore.GetMapVal(memb.PkOpen)
	dig0, err1 := merkle.VerifyMemb(label, mapVal, memb.MerkleProof)
	if err1 {
		return true
	}
	if !std.BytesEqual(dig, dig0) {
		return true
	}
	return false
}

// CheckHist errors on fail.
func CheckHist(vrfPk *cryptoffi.VrfPublicKey, uid, prefixLen uint64, dig []byte, hist []*ktcore.Memb) bool {
	var err0 bool
	for ver, memb := range hist {
		if CheckMemb(vrfPk, uid, prefixLen+uint64(ver), dig, memb) {
			err0 = true
		}
	}
	return err0
}

// CheckNonMemb errors on fail.
func CheckNonMemb(vrfPk *cryptoffi.VrfPublicKey, uid, ver uint64, dig []byte, nonMemb *ktcore.NonMemb) bool {
	label, err0 := ktcore.CheckMapLabel(vrfPk, uid, ver, nonMemb.LabelProof)
	if err0 {
		return true
	}
	dig0, err1 := merkle.VerifyNonMemb(label, nonMemb.MerkleProof)
	if err1 {
		return true
	}
	if !std.BytesEqual(dig, dig0) {
		return true
	}
	return false
}
