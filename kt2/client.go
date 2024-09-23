package kt2

import (
	"github.com/goose-lang/primitive"
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/merkle"
	"github.com/mit-pdos/pav/rpcffi"
)

type Client struct {
	uid    uint64
	myKeys [][]byte
	// cachedLinks stores for every epoch, if we've cached that link.
	cachedLinks map[uint64]*cliSigLn
	// nextEpoch is the min epoch that we haven't yet seen, a UB on seenLinks.
	nextEpoch uint64
	servCli   *rpcffi.Client
	servSigPk cryptoffi.PublicKey
	servVrfPk cryptoffi.VRFPublicKey
}

type cliSigLn struct {
	prevLink []byte
	dig      merkle.Digest
	sig      cryptoffi.Sig
	link     linkTy
}

// checkLink checks that link sig verifies and we haven't seen any
// conflicting links.
// if any of these fail, it errs and possibly returns evid.
func (c *Client) checkLink(sigLn *SignedLink) (*Evid, bool) {
	link, err0 := sigLn.check(c.servSigPk)
	if err0 {
		return nil, true
	}

	// check if epoch already exists.
	cliLn, ok0 := c.cachedLinks[sigLn.epoch]
	if ok0 && !std.BytesEqual(cliLn.link, link) {
		cachedLn := &SignedLink{epoch: sigLn.epoch, prevLink: cliLn.prevLink, dig: cliLn.dig, sig: cliLn.sig}
		evid := &Evid{sigLn0: sigLn, sigLn1: cachedLn}
		return evid, true
	}

	// check if prev epoch already exists.
	cliPrevLn, ok1 := c.cachedLinks[sigLn.epoch-1]
	if sigLn.epoch > 0 && ok1 && !std.BytesEqual(cliPrevLn.link, sigLn.prevLink) {
		cachedLn := &SignedLink{epoch: sigLn.epoch - 1, prevLink: cliPrevLn.prevLink, dig: cliPrevLn.dig, sig: cliPrevLn.sig}
		evid := &Evid{sigLn0: cachedLn, sigLn1: sigLn}
		return evid, true
	}

	// check if next epoch already exists.
	cliNextLn, ok2 := c.cachedLinks[sigLn.epoch+1]
	if sigLn.epoch+1 != 0 && ok2 && !std.BytesEqual(link, cliNextLn.prevLink) {
		cachedLn := &SignedLink{epoch: sigLn.epoch + 1, prevLink: cliNextLn.prevLink, dig: cliNextLn.dig, sig: cliNextLn.sig}
		evid := &Evid{sigLn0: sigLn, sigLn1: cachedLn}
		return evid, true
	}

	// update cache.
	c.cachedLinks[sigLn.epoch] = &cliSigLn{prevLink: sigLn.prevLink, dig: sigLn.dig, sig: sigLn.sig, link: link}
	return nil, false
}

// checkFreshLink checks if we have a fresh link, and errs if that fails.
func (c *Client) checkFreshLink(ep uint64) bool {
	// check that we're getting fresh epoch.
	if c.nextEpoch != 0 && ep < c.nextEpoch-1 {
		return true
	}

	// update max epoch. err if too high.
	if ep+1 == 0 {
		return true
	}
	c.nextEpoch = ep + 1
	return false
}

// checkVrfProof rets err if check fails.
func (c *Client) checkVrfProof(uid uint64, ver uint64, label []byte, proof []byte) bool {
	labelIn := rpcffi.Encode(&mapLabel{uid: uid, ver: ver})
	ok0 := c.servVrfPk.Verify(labelIn, label, proof)
	return !ok0
}

// checkMembProof rets err if check fails.
func (c *Client) checkMembProof(uid uint64, ver uint64, dig []byte, memb *histMembProof) bool {
	if c.checkVrfProof(uid, ver, memb.label, memb.vrfProof) {
		return true
	}
	pkHash := cryptoffi.Hash(memb.pk)
	return merkle.CheckProof(true, memb.merkProof, memb.label, pkHash, dig)
}

// checkMembProofs rets err if check fails.
func (c *Client) checkMembProofs(uid uint64, dig []byte, membs []*histMembProof) bool {
	var err0 bool
	for v, memb := range membs {
		ver := uint64(v)
		if c.checkMembProof(uid, ver, dig, memb) {
			err0 = true
			break
		}
	}
	return err0
}

// checkNonMembProof rets err if check fails.
func (c *Client) checkNonMembProof(uid uint64, ver uint64, dig []byte, nonMemb *histNonMembProof) bool {
	if c.checkVrfProof(uid, ver, nonMemb.label, nonMemb.vrfProof) {
		return true
	}
	return merkle.CheckProof(false, nonMemb.merkProof, nonMemb.label, nil, dig)
}

// checkHistProof checks the history proof and rets the latest val and epoch,
// and an err / evid if the check doesn't succeed.
func (c *Client) checkHistProof(uid uint64, proof *histProof) ([]byte, uint64, *Evid, bool) {
	evid, err0 := c.checkLink(proof.sigLn)
	if err0 {
		return nil, 0, evid, err0
	}
	if c.checkFreshLink(proof.sigLn.epoch) {
		return nil, 0, nil, true
	}
	if c.checkMembProofs(uid, proof.sigLn.dig, proof.membs) {
		return nil, 0, nil, true
	}
	nextVer := uint64(len(proof.membs))
	if c.checkNonMembProof(uid, nextVer, proof.sigLn.dig, proof.nonMemb) {
		return nil, 0, nil, true
	}
	var lastPk []byte
	if nextVer > 0 {
		lastPk = proof.membs[nextVer-1].pk
	}
	return lastPk, proof.sigLn.epoch, nil, false
}

// Get returns a pubkey and the epoch at which it was seen, or an error / evid.
func (c *Client) Get(uid uint64) ([]byte, uint64, *Evid, bool) {
	histProof := &histProof{}
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

// checkMyHist checks a history proof against our client's vals,
// or err if failed.
func (c *Client) checkMyHist(proof *histProof) bool {
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

// Put rets the epoch at which the key was put, or an error / evid.
func (c *Client) Put(newPk []byte) (uint64, *Evid, bool) {
	putArgs := &PutArgs{uid: c.uid, pk: newPk}
	histProof := &histProof{}
	err0 := c.servCli.Call("Server.Put", putArgs, histProof)
	if err0 {
		return 0, nil, true
	}
	_, epoch, evid, err1 := c.checkHistProof(c.uid, histProof)
	if err1 {
		return 0, evid, true
	}
	c.myKeys = append(c.myKeys, newPk)
	err2 := c.checkMyHist(histProof)
	if err2 {
		return 0, nil, true
	}
	return epoch, nil, false
}

// SelfMon self-monitors for the client's own key, and returns the epoch
// through which it succeeds, or an error / evid.
func (c *Client) SelfMon() (uint64, *Evid, bool) {
	histProof := &histProof{}
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

// checkLinks checks a slice of links, and rets err / evid if fail.
func (c *Client) checkLinks(sigLinks []*SignedLink) (*Evid, bool) {
	var evid0 *Evid
	var err0 bool
	for _, sigLn := range sigLinks {
		evid1, err1 := c.checkLink(sigLn)
		if err1 {
			evid0 = evid1
			err0 = true
			break
		}
	}
	return evid0, err0
}

// Audit fetches as many links as it can and checks the last link
// against the auditor.
// it rets the number of epochs audited, or an error / evid.
func (c *Client) Audit(adtrAddr uint64, adtrPk cryptoffi.PublicKey) (uint64, *Evid, bool) {
	var sigLinks []*SignedLink
	var empt struct{}
	err0 := c.servCli.Call("Server.Audit", &empt, &sigLinks)
	if err0 {
		return 0, nil, true
	}

	evid0, err1 := c.checkLinks(sigLinks)
	if err1 {
		return 0, evid0, true
	}

	// check for fresh links.
	numEpochs := uint64(len(sigLinks))
	if numEpochs == 0 {
		return 0, nil, c.nextEpoch != 0
	}
	if c.checkFreshLink(numEpochs - 1) {
		return 0, nil, true
	}

	// contact auditor.
	adtrCli, err2 := rpcffi.NewClient(adtrAddr)
	if err2 {
		return 0, nil, true
	}
	lastEpoch := numEpochs - 1
	adtrReply := &adtrEpochInfo{}
	err3 := adtrCli.Call("Auditor.Get", &lastEpoch, adtrReply)
	if err3 {
		return 0, nil, true
	}

	// verify auditor link sig.
	ok0 := adtrPk.Verify(adtrReply.link, adtrReply.adtrSig)
	if !ok0 {
		return 0, nil, true
	}

	// compare auditor link against our own.
	lastCliSigLn, ok1 := c.cachedLinks[lastEpoch]
	primitive.Assert(ok1)
	if !std.BytesEqual(lastCliSigLn.link, adtrReply.link) {
		adtrSigLn := &SignedLink{epoch: lastEpoch, prevLink: adtrReply.prevLink, dig: adtrReply.dig, sig: adtrReply.servSig}
		evid1 := &Evid{sigLn0: sigLinks[lastEpoch], sigLn1: adtrSigLn}
		return 0, evid1, true
	}
	return numEpochs, nil, false
}
