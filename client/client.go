package client

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/advrpc"
	"github.com/mit-pdos/pav/auditor"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/hashchain"
	"github.com/mit-pdos/pav/ktserde"
	"github.com/mit-pdos/pav/merkle"
	"github.com/mit-pdos/pav/server"
)

type Client struct {
	uid        uint64
	pendingPut *pendingInfo
	LastEpoch  *lastInfo
	server     *serverInfo
}

type pendingInfo struct {
	nextVer uint64
	isSome  bool
	pk      []byte
}

type lastInfo struct {
	Epoch uint64
	dig   []byte
	link  []byte
	sig   []byte
}

type serverInfo struct {
	cli    *advrpc.Client
	sigPk  cryptoffi.SigPublicKey
	vrfPk  *cryptoffi.VrfPublicKey
	vrfSig []byte
}

// ClientErr abstracts errors that potentially have irrefutable evidence.
type ClientErr struct {
	Evid *Evid
	Err  bool
}

// Put queues pk for insertion.
// if we have a pending Put, it requires the pk to be the same.
func (c *Client) Put(pk []byte) bool {
	if c.pendingPut.isSome {
		if !std.BytesEqual(c.pendingPut.pk, pk) {
			return true
		}
	} else {
		c.pendingPut.isSome = true
		c.pendingPut.pk = pk
	}
	server.CallPut(c.server.cli, c.uid, pk, c.pendingPut.nextVer)
	return false
}

// Get returns if the pk was registered and the pk.
func (c *Client) Get(uid uint64) (bool, []byte, bool) {
	chainProof, sig, hist, bound, err0 := server.CallHistory(c.server.cli, uid, c.LastEpoch.Epoch, 0)
	if err0 {
		return false, nil, true
	}
	// check.
	last, err1 := c.getChainExt(chainProof, sig)
	if err1 {
		return false, nil, true
	}
	if CheckHist(c.server.vrfPk, uid, 0, last.dig, hist) {
		return false, nil, true
	}
	boundVer := uint64(len(hist))
	if CheckNonMemb(c.server.vrfPk, uid, boundVer, last.dig, bound) {
		return false, nil, true
	}

	// update.
	c.LastEpoch = last
	if boundVer == 0 {
		return false, nil, false
	} else {
		lastKey := hist[boundVer-1]
		return true, lastKey.PkOpen.Val, false
	}
}

// SelfMon self-monitors a client's own uid in the latest epoch.
// it returns if the key changed.
// the insertion happened sometime since the last SelfMon.
func (c *Client) SelfMon() (bool, bool) {
	chainProof, sig, hist, bound, err0 := server.CallHistory(c.server.cli, c.uid, c.LastEpoch.Epoch, c.pendingPut.nextVer)
	if err0 {
		return false, true
	}
	// check.
	last, err1 := c.getChainExt(chainProof, sig)
	if err1 {
		return false, true
	}
	if CheckHist(c.server.vrfPk, c.uid, c.pendingPut.nextVer, last.dig, hist) {
		return false, true
	}
	histLen := uint64(len(hist))
	boundVer := c.pendingPut.nextVer + histLen
	if CheckNonMemb(c.server.vrfPk, c.uid, boundVer, last.dig, bound) {
		return false, true
	}

	// check consistency with pending.
	if !c.pendingPut.isSome {
		// if no pending, shouldn't have any updates.
		if histLen != 0 {
			return false, true
		}
		c.LastEpoch = last
		return false, false
	}
	// good client only has one version update at a time.
	if histLen > 1 {
		return false, false
	}
	// update hasn't yet fired.
	if histLen == 0 {
		c.LastEpoch = last
		return false, false
	}
	newKey := hist[0]
	// equals pending put.
	if !std.BytesEqual(newKey.PkOpen.Val, c.pendingPut.pk) {
		return false, false
	}

	// update.
	c.LastEpoch = last
	c.pendingPut.isSome = false
	c.pendingPut.pk = nil
	// this client controls nextVer, so no need to check for overflow.
	c.pendingPut.nextVer = std.SumAssumeNoOverflow(c.pendingPut.nextVer, 1)
	return true, false
}

func (c *Client) Audit(adtrAddr uint64, adtrPk cryptoffi.SigPublicKey) *ClientErr {
	stdErr := &ClientErr{Err: true}
	cli := advrpc.Dial(adtrAddr)
	last := c.LastEpoch
	audit := auditor.CallGet(cli, last.Epoch)
	if audit.Err {
		return stdErr
	}

	// check adtr sig for consistency under untrusted server and trusted auditor.
	// check serv sig to catch serv misbehavior.

	// vrf evidence.
	if ktserde.VerifyVrfSig(adtrPk, audit.VrfPk, audit.AdtrVrfSig) {
		return stdErr
	}
	if ktserde.VerifyVrfSig(c.server.sigPk, audit.VrfPk, audit.ServVrfSig) {
		return stdErr
	}
	vrfPkB := cryptoffi.VrfPublicKeyEncode(c.server.vrfPk)
	if !std.BytesEqual(vrfPkB, audit.VrfPk) {
		evid := &Evid{vrf: &evidVrf{vrfPk0: vrfPkB, sig0: c.server.vrfSig, vrfPk1: audit.VrfPk, sig1: audit.ServVrfSig}}
		return &ClientErr{Evid: evid, Err: true}
	}

	// link evidence.
	if ktserde.VerifyLinkSig(adtrPk, last.Epoch, audit.Link, audit.AdtrLinkSig) {
		return stdErr
	}
	if ktserde.VerifyLinkSig(c.server.sigPk, last.Epoch, audit.Link, audit.ServLinkSig) {
		return stdErr
	}
	if !std.BytesEqual(last.link, audit.Link) {
		evid := &Evid{link: &evidLink{epoch: last.Epoch, link0: last.link, sig0: last.sig, link1: audit.Link, sig1: audit.ServLinkSig}}
		return &ClientErr{Evid: evid, Err: true}
	}
	return &ClientErr{Err: false}
}

func New(uid, servAddr uint64, servPk cryptoffi.SigPublicKey) (*Client, bool) {
	cli := advrpc.Dial(servAddr)
	reply, err0 := server.CallStart(cli)
	if err0 {
		return nil, true
	}
	extLen, newDig, newLink, err1 := hashchain.Verify(reply.StartLink, reply.ChainProof)
	if err1 {
		return nil, true
	}
	// want a starting dig.
	if extLen == 0 {
		return nil, true
	}
	if !std.SumNoOverflow(reply.StartEpochLen, extLen-1) {
		return nil, true
	}
	lastEp := reply.StartEpochLen + extLen - 1
	if ktserde.VerifyLinkSig(servPk, lastEp, newLink, reply.LinkSig) {
		return nil, true
	}
	vrfPk, err2 := cryptoffi.VrfPublicKeyDecode(reply.VrfPk)
	if err2 {
		return nil, true
	}
	if ktserde.VerifyVrfSig(servPk, reply.VrfPk, reply.VrfSig) {
		return nil, true
	}

	pendingPut := &pendingInfo{}
	last := &lastInfo{Epoch: lastEp, dig: newDig, link: newLink, sig: reply.LinkSig}
	serv := &serverInfo{cli: cli, sigPk: servPk, vrfPk: vrfPk, vrfSig: reply.VrfSig}
	return &Client{uid: uid, pendingPut: pendingPut, LastEpoch: last, server: serv}, false
}

func (c *Client) getChainExt(chainProof, sig []byte) (*lastInfo, bool) {
	extLen, newDig, newLink, err0 := hashchain.Verify(c.LastEpoch.link, chainProof)
	if err0 {
		return nil, true
	}
	if extLen == 0 {
		return c.LastEpoch, false
	}
	if !std.SumNoOverflow(c.LastEpoch.Epoch, extLen) {
		return nil, true
	}
	newEp := c.LastEpoch.Epoch + extLen
	if ktserde.VerifyLinkSig(c.server.sigPk, newEp, newLink, sig) {
		return nil, true
	}
	return &lastInfo{Epoch: newEp, dig: newDig, link: newLink, sig: sig}, false
}

// CheckMemb errors on fail.
func CheckMemb(vrfPk *cryptoffi.VrfPublicKey, uid, ver uint64, dig []byte, memb *ktserde.Memb) bool {
	label, err0 := ktserde.CheckMapLabel(vrfPk, uid, ver, memb.LabelProof)
	if err0 {
		return true
	}
	mapVal := ktserde.GetMapVal(memb.PkOpen)
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
func CheckHist(vrfPk *cryptoffi.VrfPublicKey, uid, prefixLen uint64, dig []byte, hist []*ktserde.Memb) bool {
	var err0 bool
	for ver, memb := range hist {
		if CheckMemb(vrfPk, uid, prefixLen+uint64(ver), dig, memb) {
			err0 = true
		}
	}
	return err0
}

// CheckNonMemb errors on fail.
func CheckNonMemb(vrfPk *cryptoffi.VrfPublicKey, uid, ver uint64, dig []byte, nonMemb *ktserde.NonMemb) bool {
	label, err0 := ktserde.CheckMapLabel(vrfPk, uid, ver, nonMemb.LabelProof)
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
