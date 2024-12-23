package kt

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/advrpc"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/merkle"
)

type Client struct {
	uid       uint64
	nextVer   uint64
	servCli   *advrpc.Client
	servSigPk cryptoffi.SigPublicKey
	servVrfPk *cryptoffi.VrfPublicKey
	// seenDigs stores, for an epoch, if we've gotten a digest for it.
	seenDigs map[uint64]*SigDig
	// nextEpoch is the min epoch that we haven't yet seen, an UB on seenDigs.
	nextEpoch uint64
}

// ClientErr abstracts errors that potentially have irrefutable evidence.
type ClientErr struct {
	Evid *Evid
	Err  bool
}

func checkDig(servSigPk []byte, seenDigs map[uint64]*SigDig, dig *SigDig) *ClientErr {
	stdErr := &ClientErr{Err: true}
	// sig.
	err0 := CheckSigDig(dig, servSigPk)
	if err0 {
		return stdErr
	}
	// epoch not too high, which would overflow c.nextEpoch.
	if !std.SumNoOverflow(dig.Epoch, 1) {
		return stdErr
	}
	// agrees with prior digs.
	seenDig, ok0 := seenDigs[dig.Epoch]
	if ok0 && !std.BytesEqual(seenDig.Dig, dig.Dig) {
		evid := &Evid{sigDig0: dig, sigDig1: seenDig}
		return &ClientErr{Evid: evid, Err: true}
	}
	return &ClientErr{Err: false}
}

// checkLabel checks the vrf proof, computes the label, and errors on fail.
func checkLabel(servVrfPk *cryptoffi.VrfPublicKey, uid, ver uint64, proof []byte) ([]byte, bool) {
	pre := &MapLabelPre{Uid: uid, Ver: ver}
	preByt := MapLabelPreEncode(make([]byte, 0), pre)
	return servVrfPk.Verify(preByt, proof)
}

// checkMemb errors on fail.
func checkMemb(servVrfPk *cryptoffi.VrfPublicKey, uid, ver uint64, dig []byte, memb *Memb) bool {
	label, err := checkLabel(servVrfPk, uid, ver, memb.LabelProof)
	if err {
		return true
	}
	mapVal := compMapVal(memb.EpochAdded, memb.PkOpen)
	return merkle.CheckProof(true, memb.MerkProof, label, mapVal, dig)
}

// checkMembHide errors on fail.
func checkMembHide(servVrfPk *cryptoffi.VrfPublicKey, uid, ver uint64, dig []byte, memb *MembHide) bool {
	label, err := checkLabel(servVrfPk, uid, ver, memb.LabelProof)
	if err {
		return true
	}
	return merkle.CheckProof(true, memb.MerkProof, label, memb.MapVal, dig)
}

// checkHist errors on fail.
func checkHist(servVrfPk *cryptoffi.VrfPublicKey, uid uint64, dig []byte, membs []*MembHide) bool {
	var err0 bool
	for ver, memb := range membs {
		if checkMembHide(servVrfPk, uid, uint64(ver), dig, memb) {
			err0 = true
		}
	}
	return err0
}

// checkNonMemb errors on fail.
func checkNonMemb(servVrfPk *cryptoffi.VrfPublicKey, uid, ver uint64, dig []byte, nonMemb *NonMemb) bool {
	label, err := checkLabel(servVrfPk, uid, ver, nonMemb.LabelProof)
	if err {
		return true
	}
	return merkle.CheckProof(false, nonMemb.MerkProof, label, nil, dig)
}

// Put rets the epoch at which the key was put, and evid / error on fail.
func (c *Client) Put(pk []byte) (uint64, *ClientErr) {
	stdErr := &ClientErr{Err: true}
	dig, latest, bound, err0 := CallServPut(c.servCli, c.uid, pk)
	if err0 {
		return 0, stdErr
	}
	// dig.
	err1 := checkDig(c.servSigPk, c.seenDigs, dig)
	if err1.Err {
		return 0, err1
	}
	// TODO: might be able to use same <= freshness check as Get / SelfMon.
	// = case with two puts is mathematically ruled out:
	// e.g., first put: [M v1; NM v2]. second put: [M v2; NM v3].
	// altho maybe selfmon wouldn't work bc can no longer say "up thru
	// this epoch". the latest epoch might change, as per the put allowance.
	// note: doing this would simplify server spec.
	if dig.Epoch < c.nextEpoch {
		return 0, stdErr
	}
	// latest.
	if checkMemb(c.servVrfPk, c.uid, c.nextVer, dig.Dig, latest) {
		return 0, stdErr
	}
	if dig.Epoch != latest.EpochAdded {
		return 0, stdErr
	}
	if !std.BytesEqual(pk, latest.PkOpen.Val) {
		return 0, stdErr
	}
	// bound.
	if checkNonMemb(c.servVrfPk, c.uid, c.nextVer+1, dig.Dig, bound) {
		return 0, stdErr
	}
	c.seenDigs[dig.Epoch] = dig
	c.nextEpoch = dig.Epoch + 1
	// this client controls nextVer, so no need to check for overflow.
	c.nextVer = std.SumAssumeNoOverflow(c.nextVer, 1)
	return dig.Epoch, &ClientErr{Err: false}
}

// Get returns if the pk was registered, the pk, and the epoch
// at which it was seen, or an error / evid.
// Note: interaction of isReg and hist is a potential source of bugs.
// e.g., if don't track vers properly, bound could be off.
// e.g., if don't check isReg alignment with hist, could have fraud non-exis key.
func (c *Client) Get(uid uint64) (bool, []byte, uint64, *ClientErr) {
	stdErr := &ClientErr{Err: true}
	dig, hist, isReg, latest, bound, err0 := CallServGet(c.servCli, uid)
	if err0 {
		return false, nil, 0, stdErr
	}
	// dig.
	err1 := checkDig(c.servSigPk, c.seenDigs, dig)
	if err1.Err {
		return false, nil, 0, err1
	}
	if c.nextEpoch != 0 && dig.Epoch < c.nextEpoch-1 {
		return false, nil, 0, stdErr
	}
	// hist.
	if checkHist(c.servVrfPk, uid, dig.Dig, hist) {
		return false, nil, 0, stdErr
	}
	numHistVers := uint64(len(hist))
	if numHistVers > 0 && !isReg {
		return false, nil, 0, stdErr
	}
	// latest.
	if isReg && checkMemb(c.servVrfPk, uid, numHistVers, dig.Dig, latest) {
		return false, nil, 0, stdErr
	}
	// bound.
	var boundVer uint64
	if isReg {
		boundVer = numHistVers + 1
	}
	if checkNonMemb(c.servVrfPk, uid, boundVer, dig.Dig, bound) {
		return false, nil, 0, stdErr
	}
	c.seenDigs[dig.Epoch] = dig
	c.nextEpoch = dig.Epoch + 1
	return isReg, latest.PkOpen.Val, dig.Epoch, &ClientErr{Err: false}
}

// SelfMon self-monitors for the client's own key, and returns the epoch
// through which it succeeds, or evid / error on fail.
func (c *Client) SelfMon() (uint64, *ClientErr) {
	stdErr := &ClientErr{Err: true}
	dig, bound, err0 := CallServSelfMon(c.servCli, c.uid)
	if err0 {
		return 0, stdErr
	}
	// dig.
	err1 := checkDig(c.servSigPk, c.seenDigs, dig)
	if err1.Err {
		return 0, err1
	}
	if c.nextEpoch != 0 && dig.Epoch < c.nextEpoch-1 {
		return 0, stdErr
	}
	// bound.
	if checkNonMemb(c.servVrfPk, c.uid, c.nextVer, dig.Dig, bound) {
		return 0, stdErr
	}
	c.seenDigs[dig.Epoch] = dig
	c.nextEpoch = dig.Epoch + 1
	return dig.Epoch, &ClientErr{Err: false}
}

// auditEpoch checks a single epoch against an auditor, and evid / error on fail.
func auditEpoch(seenDig *SigDig, servSigPk []byte, adtrCli *advrpc.Client, adtrPk cryptoffi.SigPublicKey) *ClientErr {
	stdErr := &ClientErr{Err: true}
	adtrInfo, err0 := CallAdtrGet(adtrCli, seenDig.Epoch)
	if err0 {
		return stdErr
	}

	// check sigs.
	servDig := &SigDig{Epoch: seenDig.Epoch, Dig: adtrInfo.Dig, Sig: adtrInfo.ServSig}
	adtrDig := &SigDig{Epoch: seenDig.Epoch, Dig: adtrInfo.Dig, Sig: adtrInfo.AdtrSig}
	if CheckSigDig(servDig, servSigPk) {
		return stdErr
	}
	if CheckSigDig(adtrDig, adtrPk) {
		return stdErr
	}

	// compare against our dig.
	if !std.BytesEqual(adtrInfo.Dig, seenDig.Dig) {
		evid := &Evid{sigDig0: servDig, sigDig1: seenDig}
		return &ClientErr{Evid: evid, Err: true}
	}
	return &ClientErr{Err: false}
}

func (c *Client) Audit(adtrAddr uint64, adtrPk cryptoffi.SigPublicKey) *ClientErr {
	adtrCli := advrpc.Dial(adtrAddr)
	// check all epochs that we've seen before.
	var err0 = &ClientErr{Err: false}
	for _, dig := range c.seenDigs {
		err1 := auditEpoch(dig, c.servSigPk, adtrCli, adtrPk)
		if err1.Err {
			err0 = err1
		}
	}
	return err0
}

func NewClient(uid, servAddr uint64, servSigPk cryptoffi.SigPublicKey, servVrfPk []byte) *Client {
	c := advrpc.Dial(servAddr)
	pk := cryptoffi.VrfPublicKeyDecode(servVrfPk)
	digs := make(map[uint64]*SigDig)
	return &Client{uid: uid, servCli: c, servSigPk: servSigPk, servVrfPk: pk, seenDigs: digs}
}
