package client

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/advrpc"
	"github.com/mit-pdos/pav/auditor"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/ktserde"
	"github.com/mit-pdos/pav/merkle"
	"github.com/mit-pdos/pav/server"
)

type Client struct {
	uid          uint64
	nextVer      uint64
	isPendingPut bool
	pendingPut   []byte
	// seenDigs stores, for an epoch, if we've gotten a digest for it.
	seenDigs map[uint64]*ktserde.SigDig
	// nextEpoch bounds the entries in seenDigs.
	// storing the next (instead of last) epoch yields a correct
	// zero val on client init, with the downside of having to check
	// that nextEpoch doesn't overflow.
	nextEpoch uint64
	servCli   *advrpc.Client
	servSigPk cryptoffi.SigPublicKey
	servVrfPk *cryptoffi.VrfPublicKey
}

// ClientErr abstracts errors that potentially have irrefutable evidence.
type ClientErr struct {
	Evid *Evid
	Err  bool
}

// Put issues a Put and errors on fail.
// if there's a pending Put, it requires the pk to be the same.
func (c *Client) Put(pk []byte) bool {
	if c.isPendingPut {
		if !std.BytesEqual(c.pendingPut, pk) {
			return true
		}
	} else {
		c.isPendingPut = true
		c.pendingPut = pk
	}
	return server.CallServPut(c.servCli, c.uid, pk, c.nextVer)
}

// Get returns if the pk was registered, the pk, and the epoch
// at which it was seen, or an error / evid.
// Note: interaction of isReg and hist is a potential source of bugs.
// e.g., if don't track vers properly, bound could be off.
// e.g., if don't check isReg alignment with hist, could have fraud non-exis key.
func (c *Client) Get(uid uint64) (bool, []byte, uint64, *ClientErr) {
	stdErr := &ClientErr{Err: true}
	dig, hist, isReg, latest, bound, err0 := server.CallServGet(c.servCli, uid)
	if err0 {
		return false, nil, 0, stdErr
	}
	// dig.
	err1 := checkDig(c.servSigPk, c.seenDigs, dig)
	if err1.Err {
		return false, nil, 0, err1
	}
	if dig.Epoch+1 < c.nextEpoch {
		return false, nil, 0, stdErr
	}
	// hist.
	if CheckHist(c.servVrfPk, uid, dig.Dig, hist) {
		return false, nil, 0, stdErr
	}
	numHistVers := uint64(len(hist))
	if numHistVers > 0 && !isReg {
		return false, nil, 0, stdErr
	}
	// latest.
	if isReg && CheckMemb(c.servVrfPk, uid, numHistVers, dig.Dig, latest) {
		return false, nil, 0, stdErr
	}
	// bound.
	var boundVer uint64
	if isReg {
		boundVer = numHistVers + 1
	}
	if CheckNonMemb(c.servVrfPk, uid, boundVer, dig.Dig, bound) {
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
	dig, bound, err0 := server.CallServSelfMon(c.servCli, c.uid)
	if err0 {
		return 0, stdErr
	}
	// dig.
	err1 := checkDig(c.servSigPk, c.seenDigs, dig)
	if err1.Err {
		return 0, err1
	}
	if dig.Epoch+1 < c.nextEpoch {
		return 0, stdErr
	}
	// bound.
	if CheckNonMemb(c.servVrfPk, c.uid, c.nextVer, dig.Dig, bound) {
		return 0, stdErr
	}
	c.seenDigs[dig.Epoch] = dig
	c.nextEpoch = dig.Epoch + 1
	return dig.Epoch, &ClientErr{Err: false}
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

// auditEpoch checks a single epoch against an auditor, and evid / error on fail.
func auditEpoch(seenDig *ktserde.SigDig, servSigPk []byte, adtrCli *advrpc.Client, adtrPk cryptoffi.SigPublicKey) *ClientErr {
	stdErr := &ClientErr{Err: true}
	adtrInfo := auditor.CallAdtrGet(adtrCli, seenDig.Epoch)

	// check sigs.
	servDig := &ktserde.SigDig{Epoch: seenDig.Epoch, Dig: adtrInfo.Dig, Sig: adtrInfo.ServSig}
	adtrDig := &ktserde.SigDig{Epoch: seenDig.Epoch, Dig: adtrInfo.Dig, Sig: adtrInfo.AdtrSig}
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

func NewClient(uid, servAddr uint64, servSigPk cryptoffi.SigPublicKey, servVrfPk []byte) *Client {
	c := advrpc.Dial(servAddr)
	pk := cryptoffi.VrfPublicKeyDecode(servVrfPk)
	digs := make(map[uint64]*ktserde.SigDig)
	return &Client{uid: uid, servCli: c, servSigPk: servSigPk, servVrfPk: pk, seenDigs: digs}
}

func checkDig(servSigPk []byte, seenDigs map[uint64]*ktserde.SigDig, dig *ktserde.SigDig) *ClientErr {
	stdErr := &ClientErr{Err: true}
	// sig.
	err0 := CheckSigDig(dig, servSigPk)
	if err0 {
		return stdErr
	}
	// doesn't overflow c.nextEpoch.
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

// CheckLabel checks the vrf proof, computes the label, and errors on fail.
func CheckLabel(servVrfPk *cryptoffi.VrfPublicKey, uid, ver uint64, proof []byte) ([]byte, bool) {
	pre := &ktserde.MapLabelPre{Uid: uid, Ver: ver}
	preByt := ktserde.MapLabelPreEncode(make([]byte, 0, 16), pre)
	return servVrfPk.Verify(preByt, proof)
}

// CheckMemb errors on fail.
func CheckMemb(servVrfPk *cryptoffi.VrfPublicKey, uid, ver uint64, dig []byte, memb *ktserde.Memb) bool {
	label, err := CheckLabel(servVrfPk, uid, ver, memb.LabelProof)
	if err {
		return true
	}
	mapVal := server.CompMapVal(memb.EpochAdded, memb.PkOpen)
	return merkle.Verify(true, label, mapVal, memb.MerkleProof, dig)
}

// CheckMembHide errors on fail.
func CheckMembHide(servVrfPk *cryptoffi.VrfPublicKey, uid, ver uint64, dig []byte, memb *ktserde.MembHide) bool {
	label, err := CheckLabel(servVrfPk, uid, ver, memb.LabelProof)
	if err {
		return true
	}
	return merkle.Verify(true, label, memb.MapVal, memb.MerkleProof, dig)
}

// CheckHist errors on fail.
func CheckHist(servVrfPk *cryptoffi.VrfPublicKey, uid uint64, dig []byte, membs []*ktserde.MembHide) bool {
	var err0 bool
	for ver, memb := range membs {
		if CheckMembHide(servVrfPk, uid, uint64(ver), dig, memb) {
			err0 = true
		}
	}
	return err0
}

// CheckNonMemb errors on fail.
func CheckNonMemb(servVrfPk *cryptoffi.VrfPublicKey, uid, ver uint64, dig []byte, nonMemb *ktserde.NonMemb) bool {
	label, err := CheckLabel(servVrfPk, uid, ver, nonMemb.LabelProof)
	if err {
		return true
	}
	return merkle.Verify(false, label, nil, nonMemb.MerkleProof, dig)
}
