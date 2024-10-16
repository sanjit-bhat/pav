package kt

import (
	"github.com/goose-lang/primitive"
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/advrpc"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/merkle"
)

type Client struct {
	uid       uint64
	nextVer   uint64
	servCli   *advrpc.Client
	servSigPk cryptoffi.PublicKey
	servVrfPk *cryptoffi.VrfPublicKey
	// seenDigs stores, for an epoch, if we've gotten a commitment for it.
	seenDigs map[uint64]*SigDig
	// nextEpoch is the min epoch that we haven't yet seen, an UB on seenDigs.
	nextEpoch uint64
}

// clientErr abstracts errors in the KT client.
// maybe there's an error. if so, maybe there's irrefutable evidence.
type clientErr struct {
	evid *Evid
	err  bool
}

// checkDig checks for freshness and prior vals, and evid / err on fail.
func (c *Client) checkDig(dig *SigDig) *clientErr {
	stdErr := &clientErr{nil, true}
	// check sig.
	err0 := CheckSigDig(dig, c.servSigPk)
	if err0 {
		return stdErr
	}
	// ret early if we've already seen this epoch before.
	seenDig, ok0 := c.seenDigs[dig.Epoch]
	if ok0 {
		if !std.BytesEqual(seenDig.Dig, dig.Dig) {
			evid := &Evid{sigDig0: dig, sigDig1: seenDig}
			return &clientErr{evid, true}
		} else {
			return &clientErr{nil, false}
		}
	}
	// check for freshness.
	if c.nextEpoch != 0 && dig.Epoch < c.nextEpoch-1 {
		return stdErr
	}
	// check epoch not too high, which would overflow c.nextEpoch.
	if c.nextEpoch+1 == 0 {
		return stdErr
	}
	c.seenDigs[dig.Epoch] = dig
	c.nextEpoch = dig.Epoch + 1
	return &clientErr{nil, false}
}

// checkVrfProof errors on fail.
// TODO: if VRF pubkey is bad, does VRF.Verify still mean something?
func (c *Client) checkVrf(uid uint64, ver uint64, label []byte, proof []byte) bool {
	pre := &MapLabelPre{Uid: uid, Ver: ver}
	preByt := MapLabelPreEncode(make([]byte, 0), pre)
	return !c.servVrfPk.Verify(preByt, label, proof)
}

// checkMemb errors on fail.
func (c *Client) checkMemb(uid uint64, ver uint64, dig []byte, memb *Memb) bool {
	if c.checkVrf(uid, ver, memb.Label, memb.VrfProof) {
		return true
	}
	mapVal := compMapVal(memb.EpochAdded, memb.CommOpen)
	return merkle.CheckProof(true, memb.MerkProof, memb.Label, mapVal, dig)
}

// checkMembHide errors on fail.
func (c *Client) checkMembHide(uid uint64, ver uint64, dig []byte, memb *MembHide) bool {
	if c.checkVrf(uid, ver, memb.Label, memb.VrfProof) {
		return true
	}
	return merkle.CheckProof(true, memb.MerkProof, memb.Label, memb.MapVal, dig)
}

// checkHist errors on fail.
func (c *Client) checkHist(uid uint64, dig []byte, membs []*MembHide) bool {
	var err0 bool
	for ver0, memb := range membs {
		ver := uint64(ver0)
		if c.checkMembHide(uid, ver, dig, memb) {
			err0 = true
		}
	}
	return err0
}

// checkNonMemb errors on fail.
func (c *Client) checkNonMemb(uid uint64, ver uint64, dig []byte, nonMemb *NonMemb) bool {
	if c.checkVrf(uid, ver, nonMemb.Label, nonMemb.VrfProof) {
		return true
	}
	return merkle.CheckProof(false, nonMemb.MerkProof, nonMemb.Label, nil, dig)
}

// Put rets the epoch at which the key was put, and evid / error on fail.
func (c *Client) Put(pk []byte) (uint64, *clientErr) {
	stdErr := &clientErr{nil, true}
	dig, latest, bound, err0 := callServPut(c.servCli, c.uid, pk)
	if err0 {
		return 0, stdErr
	}
	err1 := c.checkDig(dig)
	if err1.err {
		return 0, err1
	}
	// check latest entry has right ver, epoch, pk.
	if c.checkMemb(c.uid, c.nextVer, dig.Dig, latest) {
		return 0, stdErr
	}
	if dig.Epoch != latest.EpochAdded {
		return 0, stdErr
	}
	if !std.BytesEqual(pk, latest.CommOpen.Pk) {
		return 0, stdErr
	}
	// check bound has right ver.
	if c.checkNonMemb(c.uid, c.nextVer+1, dig.Dig, bound) {
		return 0, stdErr
	}
	c.nextVer += 1
	return dig.Epoch, &clientErr{nil, false}
}

// Get returns if the pk was registered, the pk, and the epoch
// at which it was seen, or an error / evid.
// Note: interaction of isReg and hist is a potential source of bugs.
// e.g., if don't track vers properly, bound could be off.
// e.g., if don't check isReg alignment with hist, could have fraud non-exis key.
func (c *Client) Get(uid uint64) (bool, []byte, uint64, *clientErr) {
	stdErr := &clientErr{nil, true}
	dig, hist, isReg, latest, bound, err0 := callServGet(c.servCli, uid)
	if err0 {
		return false, nil, 0, stdErr
	}
	err1 := c.checkDig(dig)
	if err1.err {
		return false, nil, 0, err1
	}
	if c.checkHist(uid, dig.Dig, hist) {
		return false, nil, 0, stdErr
	}
	numHistVers := uint64(len(hist))
	// check isReg aligned with hist.
	if numHistVers > 0 && !isReg {
		return false, nil, 0, stdErr
	}
	// check latest has right ver.
	if isReg && c.checkMemb(uid, numHistVers, dig.Dig, latest) {
		return false, nil, 0, stdErr
	}
	// check bound has right ver.
	var boundVer uint64
	// if not reg, bound should have ver = 0.
	if isReg {
		boundVer = numHistVers + 1
	}
	if c.checkNonMemb(uid, boundVer, dig.Dig, bound) {
		return false, nil, 0, stdErr
	}
	return isReg, latest.CommOpen.Pk, dig.Epoch, &clientErr{nil, false}
}

// SelfMon self-monitors for the client's own key, and returns the epoch
// through which it succeeds, or evid / error on fail.
func (c *Client) SelfMon() (uint64, *clientErr) {
	stdErr := &clientErr{nil, true}
	dig, bound, err0 := callServSelfMon(c.servCli, c.uid)
	if err0 {
		return 0, stdErr
	}
	err1 := c.checkDig(dig)
	if err1.err {
		return 0, err1
	}
	if c.checkNonMemb(c.uid, c.nextVer, dig.Dig, bound) {
		return 0, stdErr
	}
	return dig.Epoch, &clientErr{nil, false}
}

// auditEpoch checks a single epoch against an auditor, and evid / error on fail.
// pre-cond: we've seen this epoch.
func (c *Client) auditEpoch(epoch uint64, adtrCli *advrpc.Client, adtrPk cryptoffi.PublicKey) *clientErr {
	stdErr := &clientErr{nil, true}
	adtrInfo, err0 := callAdtrGet(adtrCli, epoch)
	if err0 {
		return stdErr
	}

	// check sigs.
	servDig := &SigDig{Epoch: epoch, Dig: adtrInfo.Dig, Sig: adtrInfo.ServSig}
	adtrDig := &SigDig{Epoch: epoch, Dig: adtrInfo.Dig, Sig: adtrInfo.AdtrSig}
	if CheckSigDig(servDig, c.servSigPk) {
		return stdErr
	}
	if CheckSigDig(adtrDig, adtrPk) {
		return stdErr
	}

	// compare against our dig.
	seenDig, ok0 := c.seenDigs[epoch]
	primitive.Assert(ok0)
	if !std.BytesEqual(adtrInfo.Dig, seenDig.Dig) {
		evid := &Evid{sigDig0: servDig, sigDig1: seenDig}
		return &clientErr{evid, true}
	}
	return &clientErr{nil, false}
}

func (c *Client) Audit(adtrAddr uint64, adtrPk cryptoffi.PublicKey) *clientErr {
	adtrCli := advrpc.Dial(adtrAddr)
	// check all epochs that we've seen before.
	var err0 = &clientErr{nil, false}
	for ep := range c.seenDigs {
		err1 := c.auditEpoch(ep, adtrCli, adtrPk)
		if err1.err {
			err0 = err1
		}
	}
	return err0
}

func newClient(uid, servAddr uint64, servSigPk cryptoffi.PublicKey, servVrfPk *cryptoffi.VrfPublicKey) *Client {
	c := advrpc.Dial(servAddr)
	digs := make(map[uint64]*SigDig)
	return &Client{uid: uid, servCli: c, servSigPk: servSigPk, servVrfPk: servVrfPk, seenDigs: digs}
}
