package ktmerkle

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/cryptoutil"
	"github.com/mit-pdos/pav/merkle"
	"sync"
)

type epochTy = uint64
type linkTy = []byte
type errorTy = bool
type okTy = bool

const (
	errNone      errorTy = false
	errSome      errorTy = true
	noneChainTag byte    = 0
	someChainTag byte    = 1
)

// hashChain stores commitments to a series of data entries.
type hashChain []linkTy

func (c *hashChain) put(data []byte) {
	chain := *c
	chainLen := uint64(len(chain))
	if chainLen == 0 {
		h := cryptoffi.Hash([]byte{noneChainTag})
		*c = append(chain, h)
		return
	}

	lastLink := chain[chainLen-1]
	var hr cryptoutil.Hasher
	cryptoutil.HasherWrite(&hr, []byte{someChainTag})
	cryptoutil.HasherWrite(&hr, lastLink)
	cryptoutil.HasherWrite(&hr, data)
	h := cryptoutil.HasherSum(hr, nil)
	*c = append(chain, h)
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
func (ts *timeSeries) put(e epochTy, v merkle.Val, sig cryptoffi.Sig) errorTy {
	entries := *ts
	length := uint64(len(entries))
	if length == 0 {
		*ts = append(entries, timeEntry{time: e, val: v, sig: sig})
		return errNone
	}
	last := entries[length-1].time
	if e < last {
		return errSome
	}
	*ts = append(entries, timeEntry{time: e, val: v, sig: sig})
	return errNone
}

// get returns val, isInit, putPromise sig, isBoundary.
// val is the latest update val for time t.
// if no update happened before t, isInit = false and val = nil.
// if the epoch was an update boundary, isBoundary = true and putPromise is set.
func (ts *timeSeries) get(t epochTy) (merkle.Val, bool, cryptoffi.Sig, bool) {
	var latest merkle.Val
	var init bool
	var sig cryptoffi.Sig
	var boundary bool

	for _, te := range *ts {
		if te.time > t {
			continue
		}
		latest = te.val
		init = true
		sig = te.sig
		boundary = te.time == t
	}
	return latest, init, sig, boundary
}

/* Key server. */

type serv struct {
	sk     cryptoffi.PrivateKey
	mu     *sync.Mutex
	trees  []*merkle.Tree
	nextTr *merkle.Tree
	chain  hashChain
}

func newServ() (*serv, cryptoffi.PublicKey) {
	sk, pk := cryptoffi.MakeKeys()
	mu := new(sync.Mutex)
	emptyTr := &merkle.Tree{}
	trees := []*merkle.Tree{emptyTr}
	nextTr := &merkle.Tree{}
	return &serv{sk: sk, mu: mu, trees: trees, nextTr: nextTr, chain: nil}, pk
}

func (s *serv) updateEpoch() {
	s.mu.Lock()
	nextTr := s.nextTr
	dig := nextTr.Digest()
	s.chain.put(dig)
	s.trees = append(s.trees, nextTr)
	s.nextTr = nextTr.DeepCopy()
	s.mu.Unlock()
}

// put returns the epoch at which this val should be visible.
func (s *serv) put(id merkle.Id, val merkle.Val) (epochTy, cryptoffi.Sig, errorTy) {
	s.mu.Lock()
	nextEpoch := uint64(len(s.trees))
	_, _, err := s.nextTr.Put(id, val)
	enc := (&servSigSepPut{epoch: nextEpoch, id: id, val: val}).encode()
    // Before signing, 
	sig := cryptoffi.Sign(s.sk, enc)
	s.mu.Unlock()
	return nextEpoch, sig, err
}

func (s *serv) getIdAtEpoch(id merkle.Id, epoch epochTy) *servGetIdAtEpochReply {
	errReply := &servGetIdAtEpochReply{}
	errReply.err = errSome
	s.mu.Lock()
	if epoch >= uint64(len(s.trees)) {
		s.mu.Unlock()
		return errReply
	}
	tr := s.trees[epoch]
	reply := tr.Get(id)
	enc := (&servSigSepDig{epoch: epoch, dig: reply.Digest}).encode()
	sig := cryptoffi.Sign(s.sk, enc)
	s.mu.Unlock()
	return &servGetIdAtEpochReply{val: reply.Val, digest: reply.Digest, proofTy: reply.ProofTy, proof: reply.Proof, sig: sig, err: reply.Error}
}

func (s *serv) getIdLatest(id merkle.Id) *servGetIdLatestReply {
	s.mu.Lock()
	epoch := uint64(len(s.trees)) - 1
	tr := s.trees[epoch]
	reply := tr.Get(id)
	enc := (&servSigSepDig{epoch: epoch, dig: reply.Digest}).encode()
	sig := cryptoffi.Sign(s.sk, enc)
	s.mu.Unlock()
	return &servGetIdLatestReply{epoch: epoch, val: reply.Val, digest: reply.Digest, proofTy: reply.ProofTy, proof: reply.Proof, sig: sig, err: reply.Error}
}

func (s *serv) getDigest(epoch epochTy) (merkle.Digest, cryptoffi.Sig, errorTy) {
	s.mu.Lock()
	if epoch >= uint64(len(s.trees)) {
		s.mu.Unlock()
		return nil, nil, errSome
	}
	tr := s.trees[epoch]
	dig := tr.Digest()
	enc := (&servSigSepDig{epoch: epoch, dig: dig}).encode()
	sig := cryptoffi.Sign(s.sk, enc)
	s.mu.Unlock()
	return dig, sig, errNone
}

func (s *serv) getLink(epoch epochTy) (linkTy, cryptoffi.Sig, errorTy) {
	s.mu.Lock()
	if epoch >= uint64(len(s.chain)) {
		s.mu.Unlock()
		return nil, nil, errSome
	}
	ln := s.chain[epoch]
	enc := (&servSigSepLink{epoch: epoch, link: ln}).encode()
	sig := cryptoffi.Sign(s.sk, enc)
	s.mu.Unlock()
	return ln, sig, errNone
}

/* auditor */

type signedLink struct {
	link linkTy
	// Type servSigSepLink.
	sig cryptoffi.Sig
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
	return &auditor{mu: new(sync.Mutex), sk: sk, servPk: servPk}, pk
}

// put adds a link to the log. it's unspecified how this gets called.
// but we need to verify the sig / epoch to prove correctness under
// an honest server and auditor.
// sig type: servSigSepLink.
func (a *auditor) put(link linkTy, sig cryptoffi.Sig) errorTy {
	a.mu.Lock()
	epoch := uint64(len(a.log))
	enc := (&servSigSepLink{epoch: epoch, link: link}).encode()
	ok := cryptoffi.Verify(a.servPk, enc, sig)
	if !ok {
		return errSome
	}

	entry := &signedLink{link: link, sig: sig}
	a.log = append(a.log, entry)
	a.mu.Unlock()
	return errNone
}

// get returns 1) sig type: servSigSepLink, 2) sig type: adtrSigSepLink.
func (a *auditor) get(epoch epochTy) (linkTy, cryptoffi.Sig, cryptoffi.Sig, errorTy) {
	a.mu.Lock()
	if epoch >= uint64(len(a.log)) {
		a.mu.Unlock()
		return nil, nil, nil, errSome
	}
	entry := a.log[epoch]
	enc := (&adtrSigSepLink{epoch: epoch, link: entry.link}).encode()
	sig := cryptoffi.Sign(a.sk, enc)
	a.mu.Unlock()
	return entry.link, entry.sig, sig, errNone
}

/* Key client. */

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

/*
// TODO: what happens if client calls put twice in an epoch?
func (c *keyCli) put(val merkle.Val) (epochTy, errorTy) {
	epoch, err := verCallPut(c.serv, c.servPk, c.id, val)
	if err {
		return 0, err
	}
	c.myVals.put(epoch, val)
	return epoch, errNone
}
*/

/*
func (c *keyCli) get(id merkle.Id) (epochTy, merkle.Val, errorTy) {
	reply := verCallGetIdLatest(c.serv, c.servPk, id)
	if reply.error {
		return 0, nil, reply.error
	}

	origDig, ok := c.digs[reply.epoch]
	if ok && !std.BytesEqual(origDig, reply.digest) {
		return 0, nil, errSome
	}
	if !ok {
		c.digs[reply.epoch] = reply.digest
	}
	return reply.epoch, reply.val, errNone
}

func (c *keyCli) getOrFillDig(epoch epochTy) (merkle.Digest, errorTy) {
	var dig merkle.Digest
	dig, ok0 := c.digs[epoch]
	if ok0 {
		return dig, errNone
	}
	newDig, err := verCallGetDigest(c.serv, c.servPk, epoch)
	if err {
		return nil, err
	}
	c.digs[epoch] = newDig
	return newDig, errNone
}

// audit through epoch idx exclusive.
func (c *keyCli) audit(adtrId uint64) (epochTy, errorTy) {
	// Note: potential attack.
	// Key serv refuses to fill in a hole, even though we have bigger digests.
	var chain hashChain
	var epoch uint64
	// TODO: maybe factor out digest fetch into sep loop.
	// Consider doing this for other for loop as well.
	for {
		dig, err0 := c.getOrFillDig(epoch)
		if err0 {
			break
		}
		chain.put(dig)
		epoch++
	}
	if epoch == 0 {
		return 0, errSome
	}
	lastEpoch := epoch - 1

	adtr := c.adtrs[adtrId]
	adtrPk := c.adtrPks[adtrId]
	adtrLink, err1 := verCallGetLink(adtr, adtrPk, lastEpoch)
	if err1 {
		return 0, err1
	}
	link := chain[uint64(len(chain))-1]
	if !std.BytesEqual(link, adtrLink) {
		return 0, errSome
	}

	return epoch, errNone
}

func (c *keyCli) checkProofWithExpected(epoch epochTy, expVal merkle.Val, expProofTy merkle.ProofTy) okTy {
	id := c.id
	reply := verCallGetIdAtEpoch(c.serv, c.servPk, id, epoch)
	if reply.error {
		return false
	}
	if !std.BytesEqual(reply.val, expVal) {
		return false
	}
	if reply.proofTy != expProofTy {
		return false
	}
	origDig, ok := c.digs[epoch]
	if ok && !std.BytesEqual(reply.digest, origDig) {
		return false
	}
	if !ok {
		c.digs[epoch] = reply.digest
	}
	return true
}

// selfAudit through Epoch idx exclusive.
func (c *keyCli) selfAudit() epochTy {
	// TODO: maybe ret err if audit fails during an epoch we know should exist.
	var epoch epochTy
	for {
		expVal, expProofTy := c.myVals.get(epoch)
		ok := c.checkProofWithExpected(epoch, expVal, expProofTy)
		if !ok {
			break
		}
		epoch++
	}
	return epoch
}
*/
