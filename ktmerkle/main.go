package ktmerkle

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/secure-chat/cryptoffi"
	"github.com/mit-pdos/secure-chat/cryptoutil"
	"github.com/mit-pdos/secure-chat/merkle"
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

// Key server.

type keyServ struct {
	sk     cryptoffi.PrivateKey
	mu     *sync.Mutex
	trees  []*merkle.Tree
	nextTr *merkle.Tree
	chain  []linkTy
}

func newKeyServ(sk cryptoffi.PrivateKey) *keyServ {
	s := &keyServ{}
	s.sk = sk
	s.mu = new(sync.Mutex)
	emptyTr := &merkle.Tree{}
	s.trees = []*merkle.Tree{emptyTr}
	s.nextTr = &merkle.Tree{}
	s.chain = []linkTy{emptyTr.Digest()}
	return s
}

func calcNextLink(prevLink linkTy, data []byte) linkTy {
	var hr cryptoutil.Hasher
	cryptoutil.HasherWrite(&hr, data)
	cryptoutil.HasherWrite(&hr, prevLink)
	newLink := cryptoutil.HasherSum(hr, nil)
	return newLink
}

func extendChain(chain *[]linkTy, data []byte) {
	oldChain := *chain
	var prevLink linkTy
	chainLen := uint64(len(oldChain))
	if chainLen > 0 {
		prevLink = oldChain[chainLen-1]
	}
	newLink := calcNextLink(prevLink, data)
	*chain = append(oldChain, newLink)
}

func (s *keyServ) updateEpoch() {
	s.mu.Lock()
	nextTr := s.nextTr
	dig := nextTr.Digest()
	extendChain(&s.chain, dig)
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
	chain  []linkTy
}

func newAuditor(sk cryptoffi.PrivateKey, servPk cryptoffi.PublicKey) *auditor {
	return &auditor{mu: new(sync.Mutex), sk: sk, servPk: servPk, chain: nil}
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
	extendChain(&a.chain, dig)
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
	adtrs     []*urpc.Client
	adtrPks   []cryptoffi.PublicKey
	servPk    cryptoffi.PublicKey
	digs      map[epochTy]merkle.Digest
	id        merkle.Id
	serv      *urpc.Client
	valEpochs []epochTy
	vals      []merkle.Val
}

func newKeyCli(id merkle.Id, servAddr grove_ffi.Address, adtrAddrs []grove_ffi.Address, adtrPks []cryptoffi.PublicKey, servPk cryptoffi.PublicKey) *keyCli {
	serv := urpc.MakeClient(servAddr)
	var adtrs []*urpc.Client
	for _, addr := range adtrAddrs {
		adtrs = append(adtrs, urpc.MakeClient(addr))
	}
	digs := make(map[epochTy]merkle.Digest)
	return &keyCli{adtrs: adtrs, adtrPks: adtrPks, servPk: servPk, digs: digs, id: id, serv: serv, valEpochs: nil, vals: nil}
}

// TODO: what happens if client calls put twice in an epoch?
func (c *keyCli) put(val merkle.Val) (epochTy, errorTy) {
	epoch, err := verCallPut(c.serv, c.servPk, c.id, val)
	if err != errNone {
		return 0, err
	}
	c.valEpochs = append(c.valEpochs, epoch)
	c.vals = append(c.vals, val)
	return epoch, errNone
}

func (c *keyCli) get(id merkle.Id) (epochTy, merkle.Val, errorTy) {
	reply := verCallGetIdLatest(c.serv, c.servPk, id)
	if reply.error != errNone {
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
	if err != errNone {
		return nil, err
	}
	c.digs[epoch] = newDig
	return newDig, errNone
}

// audit through epoch idx exclusive.
func (c *keyCli) audit(adtrId uint64) (epochTy, errorTy) {
	// Note: potential attack.
	// Key serv refuses to fill in a hole, even though we have bigger digests.
	var link linkTy
	var epoch uint64
	// TODO: maybe factor out digest fetch into sep loop.
	// Consider doing this for other for loop as well.
	for {
		dig, err0 := c.getOrFillDig(epoch)
		if err0 != errNone {
			break
		}
		link = calcNextLink(link, dig)
		epoch++
	}
	if epoch == 0 {
		return 0, errSome
	}
	lastEpoch := epoch - 1

	adtr := c.adtrs[adtrId]
	adtrPk := c.adtrPks[adtrId]
	adtrLink, err1 := verCallGetLink(adtr, adtrPk, lastEpoch)
	if err1 != errNone {
		return 0, err1
	}
	if !std.BytesEqual(link, adtrLink) {
		return 0, errSome
	}

	return epoch, errNone
}

func (c *keyCli) checkProofWithExpected(epoch epochTy, expVal merkle.Val, expProofTy merkle.ProofTy) okTy {
	id := c.id
	reply := verCallGetIdAtEpoch(c.serv, c.servPk, id, epoch)
	if reply.error != errNone {
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
	numVals := uint64(len(c.vals))
	// valIdx points to one past the curr val.
	// This makes it easy to represent nonmembership before any puts.
	var valIdx uint64
	var epoch epochTy
	for {
		// Check if we're at the next val update.
		if valIdx != numVals {
			epochChange := c.valEpochs[valIdx]
			if epoch == epochChange {
				valIdx++
			}
		}
		var expProofTy merkle.ProofTy
		var expVal merkle.Val
		// Check if at epoch before we even sent a val.
		if valIdx != 0 {
			expProofTy = merkle.MembProofTy
			expVal = c.vals[valIdx-1]
		}
		ok := c.checkProofWithExpected(epoch, expVal, expProofTy)
		if !ok {
			break
		}
		epoch++
	}
	return epoch
}

func updateAdtrDigs(servCli, adtrCli *urpc.Client) epochTy {
	var epoch uint64 = 0
	for {
		dig, sig, err0 := callGetDigest(servCli, epoch)
		if err0 != errNone {
			break
		}
		err1 := callUpdate(adtrCli, epoch, dig, sig)
		if err1 != errNone {
			break
		}
		epoch++
	}
	return epoch
}
