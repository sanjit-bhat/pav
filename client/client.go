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
	cli   *advrpc.Client
	sigPk cryptoffi.SigPublicKey
	vrfPk *cryptoffi.VrfPublicKey
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
	audit, err0 := auditor.CallGet(cli, last.Epoch)
	if err0 {
		return stdErr
	}
	// consistency under untrusted server and trusted auditor.
	if checkLinkSig(adtrPk, last.Epoch, audit.Link, audit.AdtrSig) {
		return stdErr
	}
	// potentially catch server misbehavior.
	if checkLinkSig(c.server.sigPk, last.Epoch, audit.Link, audit.ServSig) {
		return stdErr
	}
	if !std.BytesEqual(last.link, audit.Link) {
		// TODO: simplify this.
		sd0 := &ktserde.SigDig{Epoch: last.Epoch, Dig: last.link, Sig: last.sig}
		sd1 := &ktserde.SigDig{Epoch: last.Epoch, Dig: audit.Link, Sig: audit.ServSig}
		evid := &Evid{sigDig0: sd0, sigDig1: sd1}
		return &ClientErr{Evid: evid, Err: true}
	}
	return &ClientErr{Err: false}
}

func New(uid, servAddr uint64, servSigPk cryptoffi.SigPublicKey, servVrfPk []byte) (*Client, bool) {
	cli := advrpc.Dial(servAddr)
	startEpLen, startLink, proof, sig, err0 := server.CallStartCli(cli)
	if err0 {
		return nil, true
	}
	extLen, newDig, newLink, err1 := hashchain.Verify(startLink, proof)
	if err1 {
		return nil, true
	}
	// want a starting dig.
	if extLen == 0 {
		return nil, true
	}
	if !std.SumNoOverflow(startEpLen, extLen-1) {
		return nil, true
	}
	lastEp := startEpLen + extLen - 1
	if checkLinkSig(servSigPk, lastEp, newLink, sig) {
		return nil, true
	}

	pendingPut := &pendingInfo{}
	last := &lastInfo{Epoch: lastEp, dig: newDig, link: newLink, sig: sig}
	vrfPk := cryptoffi.VrfPublicKeyDecode(servVrfPk)
	serv := &serverInfo{cli: cli, sigPk: servSigPk, vrfPk: vrfPk}
	return &Client{uid: uid, pendingPut: pendingPut, LastEpoch: last, server: serv}, false
}

func checkLinkSig(pk cryptoffi.SigPublicKey, epoch uint64, link []byte, sig []byte) bool {
	pre := &ktserde.PreSigDig{Epoch: epoch, Dig: link}
	preByt := ktserde.PreSigDigEncode(make([]byte, 0, 8+8+cryptoffi.HashLen), pre)
	return pk.Verify(preByt, sig)
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
	if checkLinkSig(c.server.sigPk, newEp, newLink, sig) {
		return nil, true
	}
	return &lastInfo{Epoch: newEp, dig: newDig, link: newLink, sig: sig}, false
}

// CheckLabel checks the vrf proof, computes the label, and errors on fail.
func CheckLabel(vrfPk *cryptoffi.VrfPublicKey, uid, ver uint64, proof []byte) ([]byte, bool) {
	pre := &ktserde.MapLabelPre{Uid: uid, Ver: ver}
	preByt := ktserde.MapLabelPreEncode(make([]byte, 0, 16), pre)
	return vrfPk.Verify(preByt, proof)
}

// CheckMemb errors on fail.
func CheckMemb(vrfPk *cryptoffi.VrfPublicKey, uid, ver uint64, dig []byte, memb *ktserde.Memb) bool {
	label, err0 := CheckLabel(vrfPk, uid, ver, memb.LabelProof)
	if err0 {
		return true
	}
	mapVal := server.CompMapVal(memb.PkOpen)
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
	label, err0 := CheckLabel(vrfPk, uid, ver, nonMemb.LabelProof)
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
