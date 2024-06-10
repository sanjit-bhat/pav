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
	errNone errorTy = false
	errSome errorTy = true
)

type hashChain []linkTy

func (c *hashChain) put(data []byte) {
	chain := *c
	var lastLink linkTy
	chainLen := uint64(len(chain))
	if chainLen > 0 {
		lastLink = chain[chainLen-1]
	}

	var hr cryptoutil.Hasher
	cryptoutil.HasherWrite(&hr, lastLink)
	cryptoutil.HasherWrite(&hr, data)
	newLink := cryptoutil.HasherSum(hr, nil)
	*c = append(chain, newLink)
}

type timeEntry struct {
	time  epochTy
	entry merkle.Val
}

type timeSeries struct {
	data []timeEntry
}

// put returns error if given old entry.
func (ts *timeSeries) put(t epochTy, e merkle.Val) errorTy {
	entries := ts.data
	length := uint64(len(entries))
	if length == 0 {
		ts.data = append(entries, timeEntry{time: t, entry: e})
		return errNone
	}
	last := entries[length-1].time
	if t < last {
		return errSome
	}
	ts.data = append(entries, timeEntry{time: t, entry: e})
	return errNone
}

// get returns true if timeSeries has been initialized.
// otherwise, it returns false and a nil value.
func (ts *timeSeries) get(t epochTy) (bool, merkle.Val) {
	var init bool
	var latest merkle.Val
	for _, te := range ts.data {
		if te.time <= t {
			init = true
			latest = te.entry
		}
	}
	return init, latest
}

// Key server.

type keyServ struct {
	sk     cryptoffi.PrivateKey
	mu     *sync.Mutex
	trees  []*merkle.Tree
	nextTr *merkle.Tree
	chain  hashChain
}

func newKeyServ(sk cryptoffi.PrivateKey) *keyServ {
	s := &keyServ{}
	s.sk = sk
	s.mu = new(sync.Mutex)
	emptyTr := &merkle.Tree{}
	s.trees = []*merkle.Tree{emptyTr}
	s.nextTr = &merkle.Tree{}
	s.chain = hashChain{}
	s.chain.put(emptyTr.Digest())
	return s
}

func (s *keyServ) updateEpoch() {
	s.mu.Lock()
	nextTr := s.nextTr
	dig := nextTr.Digest()
	s.chain.put(dig)
	s.trees = append(s.trees, nextTr)
	s.nextTr = nextTr.DeepCopy()
	s.mu.Unlock()
}

// Returns the epoch at which this val should be visible.
func (s *keyServ) put(id merkle.Id, val merkle.Val) (epochTy, cryptoffi.Sig, errorTy) {
	s.mu.Lock()
	nextEpoch := uint64(len(s.trees))
	_, _, err := s.nextTr.Put(id, val)
	enc := (&idValEpoch{id: id, val: val, epoch: nextEpoch}).encode()
	sig := cryptoffi.Sign(s.sk, enc)
	s.mu.Unlock()
	return nextEpoch, sig, err
}

func (s *keyServ) getIdAtEpoch(id merkle.Id, epoch epochTy) *getIdAtEpochReply {
	errReply := &getIdAtEpochReply{}
	errReply.error = errSome
	s.mu.Lock()
	if epoch >= uint64(len(s.trees)) {
		s.mu.Unlock()
		return errReply
	}
	tr := s.trees[epoch]
	reply := tr.Get(id)
	enc := (&epochHash{epoch: epoch, hash: reply.Digest}).encode()
	sig := cryptoffi.Sign(s.sk, enc)
	s.mu.Unlock()
	return &getIdAtEpochReply{val: reply.Val, digest: reply.Digest, proofTy: reply.ProofTy, proof: reply.Proof, sig: sig, error: reply.Error}
}

func (s *keyServ) getIdLatest(id merkle.Id) *getIdLatestReply {
	s.mu.Lock()
	lastEpoch := uint64(len(s.trees)) - 1
	tr := s.trees[lastEpoch]
	reply := tr.Get(id)
	enc := (&epochHash{epoch: lastEpoch, hash: reply.Digest}).encode()
	sig := cryptoffi.Sign(s.sk, enc)
	s.mu.Unlock()
	return &getIdLatestReply{epoch: lastEpoch, val: reply.Val, digest: reply.Digest, proofTy: reply.ProofTy, proof: reply.Proof, sig: sig, error: reply.Error}
}

func (s *keyServ) getDigest(epoch epochTy) (merkle.Digest, cryptoffi.Sig, errorTy) {
	s.mu.Lock()
	if epoch >= uint64(len(s.trees)) {
		s.mu.Unlock()
		return nil, nil, errSome
	}
	tr := s.trees[epoch]
	dig := tr.Digest()
	enc := (&epochHash{epoch: epoch, hash: dig}).encode()
	sig := cryptoffi.Sign(s.sk, enc)
	s.mu.Unlock()
	return dig, sig, errNone
}

// Auditor.

type auditor struct {
	mu     *sync.Mutex
	sk     cryptoffi.PrivateKey
	servPk cryptoffi.PublicKey
	chain  hashChain
}

func newAuditor(sk cryptoffi.PrivateKey, servPk cryptoffi.PublicKey) *auditor {
	return &auditor{mu: new(sync.Mutex), sk: sk, servPk: servPk, chain: hashChain{}}
}

func (a *auditor) update(epoch epochTy, dig merkle.Digest, sig cryptoffi.Sig) errorTy {
	a.mu.Lock()
	enc := (&epochHash{epoch: epoch, hash: dig}).encode()
	ok := cryptoffi.Verify(a.servPk, enc, sig)
	if !ok {
		a.mu.Unlock()
		return errSome
	}
	if epoch != uint64(len(a.chain)) {
		a.mu.Unlock()
		return errSome
	}
	a.chain.put(dig)
	a.mu.Unlock()
	return errNone
}

func (a *auditor) getLink(epoch epochTy) (linkTy, cryptoffi.Sig, errorTy) {
	a.mu.Lock()
	if epoch >= uint64(len(a.chain)) {
		a.mu.Unlock()
		return nil, nil, errSome
	}
	link := a.chain[epoch]
	enc := (&epochHash{epoch: epoch, hash: link}).encode()
	sig := cryptoffi.Sign(a.sk, enc)
	a.mu.Unlock()
	return link, sig, errNone
}

// Key client.

type keyCli struct {
	adtrs   []*urpc.Client
	adtrPks []cryptoffi.PublicKey
	servPk  cryptoffi.PublicKey
	digs    map[epochTy]merkle.Digest
	id      merkle.Id
	serv    *urpc.Client
	myVals  *timeSeries
}

func newKeyCli(id merkle.Id, servAddr grove_ffi.Address, adtrAddrs []grove_ffi.Address, adtrPks []cryptoffi.PublicKey, servPk cryptoffi.PublicKey) *keyCli {
	serv := urpc.MakeClient(servAddr)
	var adtrs []*urpc.Client
	for _, addr := range adtrAddrs {
		adtrs = append(adtrs, urpc.MakeClient(addr))
	}
	digs := make(map[epochTy]merkle.Digest)
	return &keyCli{adtrs: adtrs, adtrPks: adtrPks, servPk: servPk, digs: digs, id: id, serv: serv, myVals: &timeSeries{}}
}

// TODO: what happens if client calls put twice in an epoch?
func (c *keyCli) put(val merkle.Val) (epochTy, errorTy) {
	epoch, err := verCallPut(c.serv, c.servPk, c.id, val)
	if err {
		return 0, err
	}
	c.myVals.put(epoch, val)
	return epoch, errNone
}

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
	var epoch epochTy
	for {
		expProofTy, expVal := c.myVals.get(epoch)
		ok := c.checkProofWithExpected(epoch, expVal, expProofTy)
		if !ok {
			break
		}
		epoch++
	}
	return epoch
}
