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
	linkSep := (&chainSepSome{epoch: chainLen - 1, prevLink: prevLink, data: data}).encode()
	link := cryptoffi.Hash(linkSep)
	*c = append(chain, link)
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

// KT server.

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

/*
func (s *serv) getIdNow(id merkle.Id) *servGetIdNowReply {
	s.mu.Lock()
	epoch := uint64(len(s.trees)) - 1
	prevLink := s.chain.getCommit(epoch)
	sig := s.linkSigs[epoch]
	reply := s.trees[epoch].Get(id)
	s.mu.Unlock()
	return &servGetIdNowReply{epoch: epoch, prevLink: prevLink, dig: reply.Digest, sig: sig, val: reply.Val, proofTy: reply.ProofTy, proof: reply.Proof, error: reply.Error}
}
*/

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

// KT auditor.

type adtrLinkSigs struct {
	prevLink linkTy
	dig      merkle.Digest
	link     linkTy
	servSig  cryptoffi.Sig
	adtrSig  cryptoffi.Sig
}

// auditor is an append-only log of server signed links.
// e.g., the S3 auditor in WhatsApp's deployment.
type auditor struct {
	mu     *sync.Mutex
	sk     cryptoffi.PrivateKey
	servPk cryptoffi.PublicKey
	log    []*adtrLinkSigs
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
	var cachedPrevLink linkTy
	if epoch == 0 {
		linkSep := (&chainSepNone{}).encode()
		cachedPrevLink = cryptoffi.Hash(linkSep)
	} else {
		cachedPrevLink = a.log[epoch-1].link
	}
	if !std.BytesEqual(prevLink, cachedPrevLink) {
		a.mu.Unlock()
		return errSome
	}

	linkSep := (&chainSepSome{epoch: epoch, prevLink: prevLink, data: dig}).encode()
	link := cryptoffi.Hash(linkSep)
	servSep := (&servSepLink{link: link}).encode()
	servOk := cryptoffi.Verify(a.servPk, servSep, servSig)
	if !servOk {
		a.mu.Unlock()
		return errSome
	}

	adtrSep := (&adtrSepLink{link: link}).encode()
	adtrSig := cryptoffi.Sign(a.sk, adtrSep)
	entry := &adtrLinkSigs{prevLink: prevLink, dig: dig, link: link, servSig: servSig, adtrSig: adtrSig}
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

// KT client.

type cliSigLink struct {
	prevLink linkTy
	dig      merkle.Digest
	sig      cryptoffi.Sig
	link     linkTy
}

type client struct {
	id     merkle.Id
	myVals timeSeries
	links  map[epochTy]*cliSigLink
	serv   *urpc.Client
	servPk cryptoffi.PublicKey
}

func newClient(id merkle.Id, servAddr grove_ffi.Address, servPk cryptoffi.PublicKey) *client {
	serv := urpc.MakeClient(servAddr)
	digs := make(map[epochTy]*cliSigLink)
	return &client{id: id, myVals: nil, links: digs, serv: serv, servPk: servPk}
}

// evidServLink is evidence that the server signed two conflicting links,
// either zero or one epochs away.
type evidServLink struct {
	epoch0    epochTy
	prevLink0 linkTy
	dig0      merkle.Digest
	sig0      cryptoffi.Sig

	epoch1    epochTy
	prevLink1 linkTy
	dig1      merkle.Digest
	sig1      cryptoffi.Sig
}

// check returns an error if the evidence does not check out.
// otherwise, it proves that the server was dishonest.
func (e *evidServLink) check(servPk cryptoffi.PublicKey) errorTy {
	linkSep0 := (&chainSepSome{epoch: e.epoch0, prevLink: e.prevLink0, data: e.dig0}).encode()
	link0 := cryptoffi.Hash(linkSep0)
	enc0 := (&servSepLink{link: link0}).encode()
	ok0 := cryptoffi.Verify(servPk, enc0, e.sig0)
	if !ok0 {
		return errSome
	}

	linkSep1 := (&chainSepSome{epoch: e.epoch1, prevLink: e.prevLink1, data: e.dig1}).encode()
	link1 := cryptoffi.Hash(linkSep1)
	enc1 := (&servSepLink{link: link1}).encode()
	ok1 := cryptoffi.Verify(servPk, enc1, e.sig1)
	if !ok1 {
		return errSome
	}

	if e.epoch0 == e.epoch1 {
		return std.BytesEqual(link0, link1)
	}
	if e.epoch0+1 == e.epoch1 {
		return std.BytesEqual(link0, e.prevLink1)
	}
	return errSome
}

func (c *client) addLink(epoch epochTy, prevLink linkTy, dig merkle.Digest, sig cryptoffi.Sig) (*evidServLink, errorTy) {
	linkSep := (&chainSepSome{epoch: epoch, prevLink: prevLink, data: dig}).encode()
	link := cryptoffi.Hash(linkSep)
	// Check that link sig verifies.
	preSig := (&servSepLink{link: link}).encode()
	ok0 := cryptoffi.Verify(c.servPk, preSig, sig)
	if !ok0 {
		return nil, errSome
	}

	// Check if epoch already exists.
	cachedLink, ok1 := c.links[epoch]
	if ok1 && !std.BytesEqual(cachedLink.link, link) {
		evid := &evidServLink{epoch0: epoch, prevLink0: cachedLink.prevLink, dig0: cachedLink.dig, sig0: cachedLink.sig, epoch1: epoch, prevLink1: prevLink, dig1: dig, sig1: sig}
		return evid, errSome
	}

	// Check if epoch-1 already exists.
	if epoch != 0 {
		cachedPrevLink, ok2 := c.links[epoch-1]
		if ok2 && !std.BytesEqual(cachedPrevLink.link, prevLink) {
			evid := &evidServLink{epoch0: epoch - 1, prevLink0: cachedPrevLink.prevLink, dig0: cachedPrevLink.dig, sig0: cachedPrevLink.sig, epoch1: epoch, prevLink1: prevLink, dig1: dig, sig1: sig}
			return evid, errSome
		}
	}

	// Check if epoch+1 already exists.
	cachedNextLink, ok3 := c.links[epoch+1]
	if ok3 && !std.BytesEqual(link, cachedNextLink.prevLink) {
		evid := &evidServLink{epoch0: epoch, prevLink0: link, dig0: dig, sig0: sig, epoch1: epoch + 1, prevLink1: cachedNextLink.prevLink, dig1: cachedNextLink.dig, sig1: cachedNextLink.sig}
		return evid, errSome
	}

	if !ok1 {
		c.links[epoch] = &cliSigLink{prevLink: prevLink, dig: dig, sig: sig, link: link}
	}
	return nil, errNone
}

func (c *client) put(val merkle.Val) (epochTy, *evidServLink, errorTy) {
	reply := callServPut(c.serv, c.id, val)
	if reply.error {
		return 0, nil, reply.error
	}

	evid, err0 := c.addLink(reply.putEpoch-1, reply.prev2Link, reply.prevDig, reply.linkSig)
	if err0 {
		return 0, evid, err0
	}

	prePut := (&servSepPut{epoch: reply.putEpoch, id: c.id, val: val}).encode()
	ok := cryptoffi.Verify(c.servPk, prePut, reply.putSig)
	if !ok {
		return 0, nil, errSome
	}
	c.myVals.put(reply.putEpoch, val, reply.putSig)
	return reply.putEpoch, nil, errNone
}

// getAt fetches an id at a particular epoch.
func (c *client) getAt(id merkle.Id, epoch epochTy) (merkle.Val, *evidServLink, errorTy) {
	reply := callServGetIdAt(c.serv, id, epoch)
	if reply.error {
		return nil, nil, reply.error
	}

	err0 := merkle.CheckProof(reply.proofTy, reply.proof, id, reply.val, reply.dig)
	if err0 {
		return nil, nil, err0
	}

	evid, err1 := c.addLink(epoch, reply.prevLink, reply.dig, reply.sig)
	if err1 {
		return nil, evid, err1
	}
	return reply.val, nil, errNone
}

/*
// getNow fetches the latest key for a particular id.
func (c *client) getNow(id merkle.Id) (epochTy, merkle.Val, *evidServLink, errorTy) {
	reply := callServGetIdNow(c.serv, id)
	if reply.error {
		return 0, nil, nil, reply.error
	}

	err0 := merkle.CheckProof(reply.proofTy, reply.proof, id, reply.val, reply.dig)
	if err0 {
		return 0, nil, nil, err0
	}

	evid, err1 := c.addLink(reply.epoch, reply.prevLink, reply.dig, reply.sig)
	if err1 {
		return 0, nil, evid, err1
	}
	return reply.epoch, reply.val, nil, errNone
}
*/

func (c *client) fetchLink(epoch epochTy) (*evidServLink, errorTy) {
	_, ok0 := c.links[epoch]
	if ok0 {
		return nil, errNone
	}
	reply := callServGetLink(c.serv, epoch)
	if reply.error {
		return nil, reply.error
	}
	evid, err0 := c.addLink(epoch, reply.prevLink, reply.dig, reply.sig)
	if err0 {
		return evid, err0
	}
	return nil, errNone
}

// audit returns epoch idx (exclusive) thru which audit succeeded.
// there could be lots of errors, but currently, we mainly
// return an error if there's evidence.
// TODO: maybe change err handling, in selfCheck as well.
func (c *client) audit(adtrAddr grove_ffi.Address, adtrPk cryptoffi.PublicKey) (epochTy, *evidServLink, errorTy) {
	// Note: potential attack.
	// Key serv refuses to fill in a hole, even though we have bigger digests.
	var epoch uint64
	var evid *evidServLink
	var err errorTy
	for {
		evid, err = c.fetchLink(epoch)
		if err {
			break
		}
		epoch++
	}
	if epoch == 0 {
		return 0, nil, errSome
	}
	if evid != nil {
		return 0, evid, err
	}
	lastEpoch := epoch - 1
	lastLink := c.links[lastEpoch]

	adtr := urpc.MakeClient(adtrAddr)
	reply := callAdtrGet(adtr, lastEpoch)
	if reply.error {
		return 0, nil, reply.error
	}
	preAdtrLink := (&chainSepSome{epoch: lastEpoch, prevLink: reply.prevLink, data: reply.dig}).encode()
	adtrLink := cryptoffi.Hash(preAdtrLink)
	preAdtrSig := (&adtrSepLink{link: adtrLink}).encode()
	// Check adtr sig.
	adtrOk := cryptoffi.Verify(adtrPk, preAdtrSig, reply.adtrSig)
	if !adtrOk {
		return 0, nil, errSome
	}

	// Check serv sig.
	preServSig := (&servSepLink{link: adtrLink}).encode()
	servOk := cryptoffi.Verify(c.servPk, preServSig, reply.servSig)
	if !servOk {
		return 0, nil, errSome
	}

	// Check if our chain diverges from adtr.
	if !std.BytesEqual(lastLink.link, adtrLink) {
		evid := &evidServLink{epoch0: lastEpoch, prevLink0: lastLink.prevLink, dig0: lastLink.dig, sig0: lastLink.sig, epoch1: lastEpoch, prevLink1: reply.prevLink, dig1: reply.dig, sig1: reply.servSig}
		return 0, evid, errSome
	}
	return epoch, nil, errNone
}

// evidServPut is evidence when a server promises to put a value at a certain
// epoch but actually there's a different value (as evidenced by a merkle proof).
type evidServPut struct {
	epoch epochTy
	// For signed link.
	prevLink linkTy
	dig      merkle.Digest
	linkSig  cryptoffi.Sig
	// For signed put.
	id     merkle.Id
	val0   merkle.Val
	putSig cryptoffi.Sig
	// For merkle inclusion.
	val1  merkle.Val
	proof merkle.Proof
}

func (e *evidServPut) check(servPk cryptoffi.PublicKey) errorTy {
	// Proof of signing the link.
	preLink := (&chainSepSome{epoch: e.epoch, prevLink: e.prevLink, data: e.dig}).encode()
	link := cryptoffi.Hash(preLink)
	preLinkSig := (&servSepLink{link: link}).encode()
	linkOk := cryptoffi.Verify(servPk, preLinkSig, e.linkSig)
	if !linkOk {
		return errSome
	}

	// Proof of signing the put promise.
	prePut := (&servSepPut{epoch: e.epoch, id: e.id, val: e.val0}).encode()
	putOk := cryptoffi.Verify(servPk, prePut, e.putSig)
	if !putOk {
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

func (c *client) selfCheckAt(epoch epochTy) (*evidServLink, *evidServPut, errorTy) {
	reply := callServGetIdAt(c.serv, c.id, epoch)
	if reply.error {
		return nil, nil, reply.error
	}

	// Check merkle proof.
	errMerkle := merkle.CheckProof(reply.proofTy, reply.proof, c.id, reply.val, reply.dig)
	if errMerkle {
		return nil, nil, errMerkle
	}

	// Add in new link.
	linkEvid, errLink := c.addLink(epoch, reply.prevLink, reply.dig, reply.sig)
	if errLink {
		return linkEvid, nil, errLink
	}

	// Put promise upheld, and vals are as expected.
	expVal, expProofTy, putSig, isBoundary := c.myVals.get(epoch)
	if expProofTy != reply.proofTy {
		return nil, nil, errSome
	}
	if !std.BytesEqual(expVal, reply.val) {
		// The put promise is only valid on a boundary epoch.
		if isBoundary {
			ev := &evidServPut{epoch: epoch, prevLink: reply.prevLink, dig: reply.dig, linkSig: reply.sig, id: c.id, val0: expVal, putSig: putSig, val1: reply.val, proof: reply.proof}
			return nil, ev, errSome
		} else {
			return nil, nil, errSome
		}
	}
	return nil, nil, errNone
}

// selfCheck returns epoch idx (exclusive) thru which audit succeeded.
// there could be lots of errors, but currently, we mainly
// return an error if there's evidence.
func (c *client) selfCheck() (epochTy, *evidServLink, *evidServPut, errorTy) {
	var epoch epochTy
	var evidLink *evidServLink
	var evidPut *evidServPut
	var err errorTy
	for {
		evidLink, evidPut, err = c.selfCheckAt(epoch)
		if err {
			break
		}
		epoch++
	}
	if epoch == 0 {
		return 0, nil, nil, errSome
	}
	if evidLink != nil || evidPut != nil {
		return 0, evidLink, evidPut, err
	}
	return epoch, nil, nil, errNone
}
