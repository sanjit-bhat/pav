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
	// it's bounded by NextEpoch.
	seenDigs map[uint64]*ktserde.SigDig
	// NextEpoch upper bounds the length of a client's transparency history.
	// NOTE: storing the next (instead of last) epoch yields a correct
	// zero val on client init, with the downside of having to check
	// that NextEpoch doesn't overflow.
	NextEpoch uint64
	servCli   *advrpc.Client
	servSigPk cryptoffi.SigPublicKey
	servVrfPk *cryptoffi.VrfPublicKey
}

// ClientErr abstracts errors that potentially have irrefutable evidence.
type ClientErr struct {
	Evid *Evid
	Err  bool
}

// Put queues pk for insertion.
// if we have a pending Put, it requires the pk to be the same.
func (c *Client) Put(pk []byte) bool {
	if c.isPendingPut {
		if !std.BytesEqual(c.pendingPut, pk) {
			return true
		}
	} else {
		c.isPendingPut = true
		c.pendingPut = pk
	}
	server.CallServPut(c.servCli, c.uid, pk, c.nextVer)
	return false
}

// Get returns if the pk was registered and the pk.
func (c *Client) Get(uid uint64) (bool, []byte, *ClientErr) {
	stdErr := &ClientErr{Err: true}
	dig, hist, bound, err0 := server.CallServHistory(c.servCli, uid, 0)
	if err0 {
		return false, nil, stdErr
	}
	// dig.
	err1 := checkDig(c.servSigPk, c.seenDigs, dig)
	if err1.Err {
		return false, nil, err1
	}
	// old epoch <= new epoch.
	if dig.Epoch+1 < c.NextEpoch {
		return false, nil, stdErr
	}
	// hist.
	if CheckHist(c.servVrfPk, uid, 0, dig.Dig, hist) {
		return false, nil, stdErr
	}
	// bound.
	boundVer := uint64(len(hist))
	if CheckNonMemb(c.servVrfPk, uid, boundVer, dig.Dig, bound) {
		return false, nil, stdErr
	}

	c.seenDigs[dig.Epoch] = dig
	c.NextEpoch = dig.Epoch + 1
	if boundVer == 0 {
		return false, nil, &ClientErr{Err: false}
	} else {
		lastKey := hist[boundVer-1]
		return true, lastKey.PkOpen.Val, &ClientErr{Err: false}
	}
}

// SelfMon self-monitors a client's own uid in the latest epoch.
// it returns if the key changed and the insertion epoch.
func (c *Client) SelfMon() (bool, uint64, *ClientErr) {
	stdErr := &ClientErr{Err: true}
	dig, hist, bound, err0 := server.CallServHistory(c.servCli, c.uid, c.nextVer)
	if err0 {
		return false, 0, stdErr
	}
	// dig.
	err1 := checkDig(c.servSigPk, c.seenDigs, dig)
	if err1.Err {
		return false, 0, err1
	}
	// old epoch <= new epoch.
	if dig.Epoch+1 < c.NextEpoch {
		return false, 0, stdErr
	}
	// hist.
	if CheckHist(c.servVrfPk, c.uid, c.nextVer, dig.Dig, hist) {
		return false, 0, stdErr
	}
	// bound.
	histLen := uint64(len(hist))
	boundVer := c.nextVer + histLen
	if CheckNonMemb(c.servVrfPk, c.uid, boundVer, dig.Dig, bound) {
		return false, 0, stdErr
	}

	if !c.isPendingPut {
		// if no pending, shouldn't have any updates.
		if histLen != 0 {
			return false, 0, stdErr
		}
		c.seenDigs[dig.Epoch] = dig
		c.NextEpoch = dig.Epoch + 1
		return false, 0, &ClientErr{Err: false}
	}

	// good client only has one version update at a time.
	if histLen > 1 {
		return false, 0, stdErr
	}

	// update hasn't yet fired.
	if histLen == 0 {
		c.seenDigs[dig.Epoch] = dig
		c.NextEpoch = dig.Epoch + 1
		return false, 0, &ClientErr{Err: false}
	}

	newKey := hist[0]
	// update aligns with pending put.
	if !std.BytesEqual(newKey.PkOpen.Val, c.pendingPut) {
		return false, 0, stdErr
	}
	// old epoch < insert epoch.
	if newKey.EpochAdded < c.NextEpoch {
		return false, 0, stdErr
	}
	// insert epoch <= new epoch.
	if newKey.EpochAdded > dig.Epoch {
		return false, 0, stdErr
	}

	c.seenDigs[dig.Epoch] = dig
	c.NextEpoch = dig.Epoch + 1
	c.isPendingPut = false
	// this client controls nextVer, so no need to check for overflow.
	c.nextVer = std.SumAssumeNoOverflow(c.nextVer, 1)
	return true, newKey.EpochAdded, &ClientErr{Err: false}
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

func checkDig(sigPk []byte, seenDigs map[uint64]*ktserde.SigDig, dig *ktserde.SigDig) *ClientErr {
	stdErr := &ClientErr{Err: true}
	// sig.
	err0 := CheckSigDig(dig, sigPk)
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
	mapVal := server.CompMapVal(memb.EpochAdded, memb.PkOpen)
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
