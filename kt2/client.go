package kt2

import (
	"github.com/goose-lang/primitive"
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/merkle"
	"github.com/mit-pdos/pav/rpcffi"
)

type Client struct {
	uid       uint64
	myKeys    [][]byte
	servCli   *rpcffi.Client
	servSigPk cryptoffi.PublicKey
	servVrfPk cryptoffi.VRFPublicKey
	// seenDigs stores, for an epoch, if we've gotten a commitment for it.
	seenDigs map[uint64]*SigDig
	// nextEpoch is the min epoch that we haven't yet seen, an UB on seenDigs.
	nextEpoch uint64
}

// checkDig checks a new dig against seen digs, and evid / err on fail.
func (c *Client) checkDig(sigDig *SigDig) (*Evid, bool) {
	err0 := sigDig.Check(c.servSigPk)
	if err0 {
		return nil, true
	}
	seenDig, ok0 := c.seenDigs[sigDig.Epoch]
	if ok0 && !std.BytesEqual(seenDig.Dig, sigDig.Dig) {
		evid := &Evid{sigDig0: sigDig, sigDig1: seenDig}
		return evid, true
	}
	if !ok0 {
		c.seenDigs[sigDig.Epoch] = sigDig
	}
	return nil, false
}

// checkFreshEpoch errors on fail.
func (c *Client) checkFreshEpoch(epoch uint64) bool {
	if c.nextEpoch != 0 && epoch < c.nextEpoch-1 {
		return true
	}
	// update max epoch. err if too high.
	if epoch+1 == 0 {
		return true
	}
	c.nextEpoch = epoch + 1
	return false
}

// checkVrfProof errors on fail.
func (c *Client) checkVrfProof(uid uint64, ver uint64, label []byte, proof []byte) bool {
	preLabel := rpcffi.Encode(&mapLabel{uid: uid, ver: ver})
	return !c.servVrfPk.Verify(preLabel, label, proof)
}

// checkMembProof errors on fail.
func (c *Client) checkMembProof(uid uint64, ver uint64, dig []byte, memb *histMembProof) bool {
	if c.checkVrfProof(uid, ver, memb.label, memb.vrfProof) {
		return true
	}
	pkHash := cryptoffi.Hash(memb.pk)
	return merkle.CheckProof(true, memb.merkProof, memb.label, pkHash, dig)
}

// checkMembProofs errors on fail.
func (c *Client) checkMembProofs(uid uint64, dig []byte, membs []*histMembProof) bool {
	var err0 bool
	for verS, memb := range membs {
		ver := uint64(verS)
		if c.checkMembProof(uid, ver, dig, memb) {
			err0 = true
			break
		}
	}
	return err0
}

// checkNonMembProof errors on fail.
func (c *Client) checkNonMembProof(uid uint64, ver uint64, dig []byte, nonMemb *histNonMembProof) bool {
	if c.checkVrfProof(uid, ver, nonMemb.label, nonMemb.vrfProof) {
		return true
	}
	return merkle.CheckProof(false, nonMemb.merkProof, nonMemb.label, nil, dig)
}

// checkHistProof checks the history proof and rets the latest val and epoch,
// and an err / evid if check fails.
func (c *Client) checkHistProof(uid uint64, proof *HistProof) ([]byte, uint64, *Evid, bool) {
	evid, err0 := c.checkDig(proof.sigDig)
	if err0 {
		return nil, 0, evid, err0
	}
	epoch := proof.sigDig.Epoch
	dig := proof.sigDig.Dig
	if c.checkFreshEpoch(epoch) {
		return nil, 0, nil, true
	}
	if c.checkMembProofs(uid, dig, proof.membs) {
		return nil, 0, nil, true
	}
	nextVer := uint64(len(proof.membs))
	if c.checkNonMembProof(uid, nextVer, dig, proof.nonMemb) {
		return nil, 0, nil, true
	}
	var lastPk []byte
	if nextVer > 0 {
		lastPk = proof.membs[nextVer-1].pk
	}
	return lastPk, epoch, nil, false
}

// Get returns a pubkey and the epoch at which it was seen, or an error / evid.
func (c *Client) Get(uid uint64) ([]byte, uint64, *Evid, bool) {
	histProof := &HistProof{}
	err0 := c.servCli.Call("Server.Get", &uid, histProof)
	if err0 {
		return nil, 0, nil, true
	}
	pk, epoch, evid, err1 := c.checkHistProof(uid, histProof)
	if err1 {
		return nil, 0, evid, err1
	}
	return pk, epoch, nil, false
}

// checkMyHist checks a history proof against our own pk's,
// and errors on fail.
func (c *Client) checkMyHist(proof *HistProof) bool {
	if uint64(len(c.myKeys)) != uint64(len(proof.membs)) {
		return true
	}
	var err0 bool
	for ver := uint64(0); ver < uint64(len(c.myKeys)); ver++ {
		myKey := c.myKeys[ver]
		otherKey := proof.membs[ver].pk
		if !std.BytesEqual(myKey, otherKey) {
			err0 = true
			break
		}
	}
	return err0
}

// Put rets the epoch at which the key was put, and evid / error on fail.
func (c *Client) Put(pk []byte) (uint64, *Evid, bool) {
	putArgs := &PutArgs{uid: c.uid, pk: pk}
	histProof := &HistProof{}
	err0 := c.servCli.Call("Server.Put", putArgs, histProof)
	if err0 {
		return 0, nil, true
	}
	_, epoch, evid, err1 := c.checkHistProof(c.uid, histProof)
	if err1 {
		return 0, evid, true
	}
	c.myKeys = append(c.myKeys, pk)
	err2 := c.checkMyHist(histProof)
	if err2 {
		return 0, nil, true
	}
	return epoch, nil, false
}

// SelfMon self-monitors for the client's own key, and returns the epoch
// through which it succeeds, or evid / error on fail.
func (c *Client) SelfMon() (uint64, *Evid, bool) {
	histProof := &HistProof{}
	err0 := c.servCli.Call("Server.Get", &c.uid, histProof)
	if err0 {
		return 0, nil, true
	}
	_, epoch, evid, err1 := c.checkHistProof(c.uid, histProof)
	if err1 {
		return 0, evid, err1
	}
	err2 := c.checkMyHist(histProof)
	if err2 {
		return 0, nil, true
	}
	return epoch, nil, false
}

// auditEpoch checks a single epoch against an auditor, and evid / error on fail.
func (c *Client) auditEpoch(epoch uint64, adtrCli *rpcffi.Client, adtrPk cryptoffi.PublicKey) (*Evid, bool) {
	adtrInfo := &adtrEpochInfo{}
	err0 := adtrCli.Call("Auditor.Get", &epoch, adtrInfo)
	if err0 {
		return nil, true
	}

	// check sigs.
	servSigDig := &SigDig{Epoch: epoch, Dig: adtrInfo.dig, Sig: adtrInfo.servSig}
	adtrSigDig := &SigDig{Epoch: epoch, Dig: adtrInfo.dig, Sig: adtrInfo.adtrSig}
	if servSigDig.Check(c.servSigPk) {
		return nil, true
	}
	if adtrSigDig.Check(adtrPk) {
		return nil, true
	}

	// compare against our dig.
	seenDig, ok0 := c.seenDigs[epoch]
	primitive.Assert(ok0)
	if !std.BytesEqual(adtrInfo.dig, seenDig.Dig) {
		evid := &Evid{sigDig0: servSigDig, sigDig1: seenDig}
		return evid, true
	}
	return nil, false
}

func (c *Client) Audit(adtrAddr uint64, adtrPk cryptoffi.PublicKey) (*Evid, bool) {
	adtrCli, err0 := rpcffi.NewClient(adtrAddr)
	if err0 {
		return nil, true
	}

	// check all epochs that we've seen before.
	var evid0 *Evid
	var err1 bool
	for ep := range c.seenDigs {
		evid1, err2 := c.auditEpoch(ep, adtrCli, adtrPk)
		if err2 {
			evid0 = evid1
			err1 = true
			break
		}
	}
	return evid0, err1
}
