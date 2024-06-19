package ktmerkle

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/merkle"
	"sync"
)

type epochTy = uint64
type linkTy = []byte
type errorTy = bool
type okTy = bool

const (
	errNone errorTy = false
	errSome errorTy = true
)

// hashChain supports fast commitments to prefixes of a list.
type hashChain []linkTy

func newHashChain() hashChain {
	enc := (&chainSepNone{}).encode()
	h := cryptoffi.Hash(enc)
	var c hashChain
	c = append(c, h)
	return c
}

func (c *hashChain) put(data []byte) {
	chain := *c
	chainLen := uint64(len(chain))
	prevLink := chain[chainLen-1]
	enc := (&chainSepSome{epoch: chainLen - 1, prevLink: prevLink, data: data}).encode()
	h := cryptoffi.Hash(enc)
	*c = append(chain, h)
}

func (c hashChain) getCommit(length uint64) linkTy {
	return c[length]
}

type timeEntry struct {
	time epochTy
	val  merkle.Val
	// Type servSigSepPut.
	sig cryptoffi.Sig
}

// timeSeries converts a series of value updates into a view of the latest value
// at any given time.
type timeSeries []timeEntry

// put returns error if given old entry.
func (ts *timeSeries) put(epoch epochTy, val merkle.Val, sig cryptoffi.Sig) errorTy {
	entries := *ts
	length := uint64(len(entries))
	if length == 0 {
		*ts = append(entries, timeEntry{time: epoch, val: val, sig: sig})
		return errNone
	}
	last := entries[length-1].time
	if epoch < last {
		return errSome
	}
	*ts = append(entries, timeEntry{time: epoch, val: val, sig: sig})
	return errNone
}

// get returns val, isInit, putPromise sig, isBoundary.
// val is the latest update val for time t.
// if no update happened before t, isInit = false and val = nil.
// if the epoch was an update boundary, isBoundary = true and putPromise is set.
func (ts *timeSeries) get(epoch epochTy) (merkle.Val, bool, cryptoffi.Sig, bool) {
	var latest merkle.Val
	var init bool
	var sig cryptoffi.Sig
	var boundary bool

	for _, te := range *ts {
		if te.time > epoch {
			continue
		}
		latest = te.val
		init = true
		sig = te.sig
		boundary = te.time == epoch
	}
	return latest, init, sig, boundary
}

/* Key server. */

type serv struct {
	sk       cryptoffi.PrivateKey
	mu       *sync.Mutex
	trees    []*merkle.Tree
	nextTr   *merkle.Tree
	chain    hashChain
	linkSigs []cryptoffi.Sig
	// Whether an ID has been changed in the next epoch.
	changed map[string]bool
}

func newServ() (*serv, cryptoffi.PublicKey) {
	sk, pk := cryptoffi.MakeKeys()
	mu := new(sync.Mutex)
	nextTr := &merkle.Tree{}
	changed := make(map[string]bool)

	// epoch 0 is empty tree so we can serve early get reqs.
	emptyTr := &merkle.Tree{}
	trees := []*merkle.Tree{emptyTr}
	chain := newHashChain()
	chain.put(emptyTr.Digest())
	link := chain.getCommit(1)
	enc := (&servSepLink{link: link}).encode()
	sig := cryptoffi.Sign(sk, enc)
	var sigs []cryptoffi.Sig
	sigs = append(sigs, sig)
	return &serv{sk: sk, mu: mu, trees: trees, nextTr: nextTr, chain: chain, linkSigs: sigs, changed: changed}, pk
}

func (s *serv) updateEpoch() {
	s.mu.Lock()
	commitTr := s.nextTr
	s.nextTr = commitTr.DeepCopy()
	s.trees = append(s.trees, commitTr)
	numTrees := uint64(len(s.trees))
	s.changed = make(map[string]bool)

	dig := commitTr.Digest()
	s.chain.put(dig)
	link := s.chain.getCommit(numTrees)
	enc := (&servSepLink{link: link}).encode()
	sig := cryptoffi.Sign(s.sk, enc)
	s.linkSigs = append(s.linkSigs, sig)
	s.mu.Unlock()
}

// put schedules a put to be committed at the next epoch update.
func (s *serv) put(id merkle.Id, val merkle.Val) *servPutReply {
	s.mu.Lock()
	errReply := &servPutReply{}
	errReply.error = errSome

	idS := string(id)
	changed, ok := s.changed[idS]
	if ok && changed {
		s.mu.Unlock()
		return errReply
	}
	s.changed[idS] = true
	_, _, err := s.nextTr.Put(id, val)
	if err {
		s.mu.Unlock()
		return errReply
	}

	currEpoch := uint64(len(s.trees)) - 1
	prev2Link := s.chain.getCommit(currEpoch)
	prevDig := s.trees[currEpoch].Digest()
	linkSig := s.linkSigs[currEpoch]

	putPre := (&servSepPut{epoch: currEpoch + 1, id: id, val: val}).encode()
	putSig := cryptoffi.Sign(s.sk, putPre)
	s.mu.Unlock()
	return &servPutReply{putEpoch: currEpoch + 1, prev2Link: prev2Link, prevDig: prevDig, linkSig: linkSig, putSig: putSig, error: errNone}
}

func (s *serv) getIdAt(id merkle.Id, epoch epochTy) *servGetIdAtReply {
	s.mu.Lock()
	errReply := &servGetIdAtReply{}
	errReply.error = errSome
	if epoch >= uint64(len(s.trees)) {
		s.mu.Unlock()
		return errReply
	}
	prevLink := s.chain.getCommit(epoch)
	sig := s.linkSigs[epoch]
	reply := s.trees[epoch].Get(id)
	s.mu.Unlock()
	return &servGetIdAtReply{prevLink: prevLink, dig: reply.Digest, sig: sig, val: reply.Val, proofTy: reply.ProofTy, proof: reply.Proof, error: reply.Error}
}

func (s *serv) getIdNow(id merkle.Id) *servGetIdNowReply {
	s.mu.Lock()
	epoch := uint64(len(s.trees)) - 1
	prevLink := s.chain.getCommit(epoch)
	sig := s.linkSigs[epoch]
	reply := s.trees[epoch].Get(id)
	s.mu.Unlock()
	return &servGetIdNowReply{epoch: epoch, prevLink: prevLink, dig: reply.Digest, sig: sig, val: reply.Val, proofTy: reply.ProofTy, proof: reply.Proof, error: reply.Error}
}

func (s *serv) getLink(epoch epochTy) *servGetLinkReply {
	s.mu.Lock()
	if epoch >= uint64(len(s.trees)) {
		errReply := &servGetLinkReply{}
		errReply.error = errSome
		s.mu.Unlock()
		return errReply
	}
	prevLink := s.chain.getCommit(epoch)
	dig := s.trees[epoch].Digest()
	sig := s.linkSigs[epoch]
	s.mu.Unlock()
	return &servGetLinkReply{prevLink: prevLink, dig: dig, sig: sig, error: errNone}
}

/* auditor */

type signedLink struct {
	prevLink linkTy
	dig      merkle.Digest
	servSig  cryptoffi.Sig
	adtrSig  cryptoffi.Sig
}

// auditor is an append-only log of server signed links.
// e.g., the S3 auditor in WhatsApp's deployment.
type auditor struct {
	mu     *sync.Mutex
	sk     cryptoffi.PrivateKey
	servPk cryptoffi.PublicKey
	log    []*signedLink
}

func newAuditor(servPk cryptoffi.PublicKey) (*auditor, cryptoffi.PublicKey) {
	sk, pk := cryptoffi.MakeKeys()
	return &auditor{mu: new(sync.Mutex), sk: sk, servPk: servPk, log: nil}, pk
}

// put adds a link to the log. it's unspecified how this gets called.
// but we need to verify the sig / epoch to prove correctness under
// an honest server and auditor.
func (a *auditor) put(prevLink linkTy, dig merkle.Digest, servSig cryptoffi.Sig) errorTy {
	a.mu.Lock()
	epoch := uint64(len(a.log))
	linkSep := (&chainSepSome{epoch: epoch, prevLink: prevLink, data: dig}).encode()
	link := cryptoffi.Hash(linkSep)
	servSep := (&servSepLink{link: link}).encode()
	ok := cryptoffi.Verify(a.servPk, servSep, servSig)
	if !ok {
		return errSome
	}

	adtrSep := (&adtrSepLink{link: link}).encode()
	adtrSig := cryptoffi.Sign(a.sk, adtrSep)
	entry := &signedLink{prevLink: prevLink, dig: dig, servSig: servSig, adtrSig: adtrSig}
	a.log = append(a.log, entry)
	a.mu.Unlock()
	return errNone
}

// get returns the signed link at a particular epoch.
func (a *auditor) get(epoch epochTy) *adtrGetReply {
	a.mu.Lock()
	if epoch >= uint64(len(a.log)) {
		errReply := &adtrGetReply{}
		errReply.error = errSome
		a.mu.Unlock()
		return errReply
	}
	entry := a.log[epoch]
	a.mu.Unlock()
	return &adtrGetReply{prevLink: entry.prevLink, dig: entry.dig, servSig: entry.servSig, adtrSig: entry.adtrSig, error: errNone}
}

/* Key client. */

/*
type signedDig struct {
	dig merkle.Digest
	// Type: servSigSepDig.
	sig cryptoffi.Sig
}

type client struct {
	id      merkle.Id
	myVals  timeSeries
	digs    map[epochTy]*signedDig
	adtrs   []*urpc.Client
	adtrPks []cryptoffi.PublicKey
	serv    *urpc.Client
	servPk  cryptoffi.PublicKey
}

func newClient(id merkle.Id, servAddr grove_ffi.Address, adtrAddrs []grove_ffi.Address, adtrPks []cryptoffi.PublicKey, servPk cryptoffi.PublicKey) *client {
	serv := urpc.MakeClient(servAddr)
	var adtrs []*urpc.Client
	for _, addr := range adtrAddrs {
		adtrs = append(adtrs, urpc.MakeClient(addr))
	}
	digs := make(map[epochTy]*signedDig)
	return &client{id: id, myVals: nil, digs: digs, adtrs: adtrs, adtrPks: adtrPks, serv: serv, servPk: servPk}
}

func (c *client) put(val merkle.Val) (epochTy, errorTy) {
	// call rpc, check the server putpromise sig,
	// store it for later in the timeSeries.
	epoch, sig, err := callServPut(c.serv, c.id, val)
	if err {
		return 0, err
	}
	enc := (&servSepPut{epoch: epoch, id: c.id, val: val}).encode()
	ok := cryptoffi.Verify(c.servPk, enc, sig)
	if !ok {
		return 0, errSome
	}
	c.myVals.put(epoch, val, sig)
	return epoch, errNone
}

// evidServDig is evidence that the server signed two diff digs for the same epoch.
type evidServDig struct {
	epoch epochTy
	dig0  merkle.Digest
	sig0  cryptoffi.Sig
	dig1  merkle.Digest
	sig1  cryptoffi.Sig
}

// check returns an error if the evidence does not check out.
func (e *evidServDig) check(servPk cryptoffi.PublicKey) errorTy {
	enc0 := (&servSepDig{epoch: e.epoch, dig: e.dig0}).encode()
	ok0 := cryptoffi.Verify(servPk, enc0, e.sig0)
	if !ok0 {
		return errSome
	}
	enc1 := (&servSepDig{epoch: e.epoch, dig: e.dig1}).encode()
	ok1 := cryptoffi.Verify(servPk, enc1, e.sig1)
	if !ok1 {
		return errSome
	}
	if std.BytesEqual(e.dig0, e.dig1) {
		return errSome
	}
	return errNone
}

// get returns an evidence object and error if irrefutable evidence is found.
func (c *client) get(id merkle.Id) (epochTy, merkle.Val, *evidServDig, errorTy) {
	reply := callServGetIdNow(c.serv, id)
	if reply.error {
		return 0, nil, nil, reply.error
	}
	enc := (&servSepDig{epoch: reply.epoch, dig: reply.digest}).encode()
	ok := cryptoffi.Verify(c.servPk, enc, reply.sig)
	if !ok {
		return 0, nil, nil, errSome
	}

	origDig, ok := c.digs[reply.epoch]
	if ok && !std.BytesEqual(origDig.dig, reply.digest) {
		ev := &evidServDig{epoch: reply.epoch, dig0: origDig.dig, sig0: origDig.sig, dig1: reply.digest, sig1: reply.sig}
		return 0, nil, ev, errSome
	}
	if !ok {
		c.digs[reply.epoch] = &signedDig{dig: reply.digest, sig: reply.sig}
	}
	return reply.epoch, reply.val, nil, errNone
}

func (c *client) getOrFillDig(epoch epochTy) (merkle.Digest, cryptoffi.Sig, errorTy) {
	origDig, ok0 := c.digs[epoch]
	if ok0 {
		return origDig.dig, origDig.sig, errNone
	}
	dig, sig, err := callServGetDig(c.serv, epoch)
	if err {
		return nil, nil, errSome
	}
	enc := (&servSepDig{epoch: epoch, dig: dig}).encode()
	ok := cryptoffi.Verify(c.servPk, enc, sig)
	if !ok {
		return nil, nil, errSome
	}
	c.digs[epoch] = &signedDig{dig: dig, sig: sig}
	return dig, sig, errNone
}

// evidServChain is evidence that the server signed two diff chains.
type evidServChain struct {
	epoch epochTy
	digs0 []merkle.Digest
	sigs0 []cryptoffi.Sig
	link1 linkTy
	sig1  cryptoffi.Sig
}

// check returns an error if the evidence does not check out.
func (e *evidServChain) check(servPk cryptoffi.PublicKey) errorTy {
	if e.epoch == 0 {
		return errSome
	}
	digsLen := uint64(len(e.digs0))
	sigsLen := uint64(len(e.sigs0))
	if digsLen != sigsLen {
		return errSome
	}
	if digsLen != e.epoch {
		return errSome
	}

	var badSig bool
	var chain hashChain
	for i := uint64(0); i < e.epoch; i++ {
		dig := e.digs0[i]
		sig := e.sigs0[i]
		enc0 := (&servSepDig{epoch: i, dig: dig}).encode()
		ok0 := cryptoffi.Verify(servPk, enc0, sig)
		if !ok0 {
			badSig = true
		}
		chain.put(dig)
	}
	if badSig {
		return errSome
	}
	link := chain[uint64(len(chain))-1]

	enc1 := (&servSepLink{epoch: e.epoch, link: e.link1}).encode()
	ok1 := cryptoffi.Verify(servPk, enc1, e.sig1)
	if !ok1 {
		return errSome
	}

	if std.BytesEqual(link, e.link1) {
		return errSome
	}
	return errNone
}

// audit returns epoch idx (exclusive) thru which audit succeeded.
func (c *client) audit(adtrId uint64) (epochTy, *evidServChain, errorTy) {
	// Note: potential attack.
	// Key serv refuses to fill in a hole, even though we have bigger digests.
	var epoch uint64
	var chain hashChain
	var digs []merkle.Digest
	var sigs []cryptoffi.Sig
	for {
		dig, sig, err0 := c.getOrFillDig(epoch)
		if err0 {
			break
		}
		chain.put(dig)
		digs = append(digs, dig)
		sigs = append(sigs, sig)
		epoch++
	}
	if epoch == 0 {
		return 0, nil, errSome
	}
	lastEpoch := epoch - 1
	myLink := chain[uint64(len(chain))-1]

	adtr := c.adtrs[adtrId]
	adtrPk := c.adtrPks[adtrId]
	adtrLink, servSig, adtrSig, err1 := callAdtrGet(adtr, lastEpoch)
	if err1 {
		return 0, nil, err1
	}
	enc0 := (&adtrSepLink{epoch: lastEpoch, link: adtrLink}).encode()
	ok0 := cryptoffi.Verify(adtrPk, enc0, adtrSig)
	// Adtr sig failed.
	if !ok0 {
		return 0, nil, errSome
	}
	enc1 := (&servSepLink{epoch: lastEpoch, link: adtrLink}).encode()
	ok1 := cryptoffi.Verify(c.servPk, enc1, servSig)
	// Adtr should return valid server sig.
	if !ok1 {
		return 0, nil, errSome
	}

	// Serv lied to us about the chain.
	if !std.BytesEqual(myLink, adtrLink) {
		ev := &evidServChain{epoch: lastEpoch, digs0: digs, sigs0: sigs, link1: adtrLink, sig1: servSig}
		return 0, ev, errSome
	}
	return epoch, nil, errNone
}

// evidServPut is evidence when a server promises to put a value at a certain
// epoch but actually there's a different value.
type evidServPut struct {
	epoch epochTy
	// For signed dig.
	dig    merkle.Digest
	sigDig cryptoffi.Sig
	// For signed put.
	id     merkle.Id
	val0   merkle.Val
	sigPut cryptoffi.Sig
	// For merkle inclusion.
	val1  merkle.Val
	proof merkle.Proof
}

func (e *evidServPut) check(servPk cryptoffi.PublicKey) errorTy {
	// Proof of signing the digest.
	enc0 := (&servSepDig{epoch: e.epoch, dig: e.dig}).encode()
	ok0 := cryptoffi.Verify(servPk, enc0, e.sigDig)
	if !ok0 {
		return errSome
	}

	// Proof of signing the put promise.
	enc1 := (&servSepPut{epoch: e.epoch, id: e.id, val: e.val0}).encode()
	ok1 := cryptoffi.Verify(servPk, enc1, e.sigPut)
	if !ok1 {
		return errSome
	}

	// Proof of merkle inclusion of the other val.
	err0 := merkle.CheckProof(merkle.MembProofTy, e.proof, e.id, e.val1, e.dig)
	if err0 {
		return errSome
	}

	if std.BytesEqual(e.val0, e.val1) {
		return errSome
	}
	return errNone
}

func (c *client) selfAuditAt(epoch epochTy) (*evidServDig, *evidServPut, errorTy) {
	reply := callServGetIdAt(c.serv, c.id, epoch)
	if reply.error {
		return nil, nil, reply.error
	}
	// Server dig sig verifies.
	enc0 := (&servSepDig{epoch: epoch, dig: reply.digest}).encode()
	ok0 := cryptoffi.Verify(c.servPk, enc0, reply.sig)
	if !ok0 {
		return nil, nil, errSome
	}

	// We have the same stored dig.
	origDig, ok1 := c.digs[epoch]
	if ok1 && !std.BytesEqual(origDig.dig, reply.digest) {
		ev := &evidServDig{epoch: epoch, dig0: origDig.dig, sig0: origDig.sig, dig1: reply.digest, sig1: reply.sig}
		return ev, nil, errSome
	}

	// Merkle proof works.
	err0 := merkle.CheckProof(reply.proofTy, reply.proof, c.id, reply.val, reply.digest)
	if err0 {
		return nil, nil, err0
	}

	// Put promise upheld, and vals are as expected.
	expVal, expProofTy, putSig, isBoundary := c.myVals.get(epoch)
	if expProofTy != reply.proofTy {
		return nil, nil, errSome
	}
	if !std.BytesEqual(expVal, reply.val) {
		// The put promise is only valid on a boundary epoch.
		if isBoundary {
			ev := &evidServPut{epoch: epoch, dig: reply.digest, sigDig: reply.sig, id: c.id, val0: expVal, sigPut: putSig, val1: reply.val, proof: reply.proof}
			return nil, ev, errSome
		} else {
			return nil, nil, errSome
		}
	}
	return nil, nil, errNone
}

// selfAudit returns epoch idx (exclusive) thru which audit succeeded.
func (c *client) selfAudit() (epochTy, *evidServDig, *evidServPut, errorTy) {
	// TODO: maybe ret err if audit fails during an epoch we know should exist.
	var epoch epochTy
	var evidDig *evidServDig
	var evidPut *evidServPut
	var err errorTy
	for {
		r0, r1, r2 := c.selfAuditAt(epoch)
		evidDig = r0
		evidPut = r1
		err = r2
		if r2 {
			break
		}
		epoch++
	}
	return epoch, evidDig, evidPut, err
}
*/
