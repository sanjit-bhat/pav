package ktMerkle

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/secure-chat/cryptoFFI"
	"github.com/mit-pdos/secure-chat/cryptoHelpers"
	"github.com/mit-pdos/secure-chat/merkle"
	"github.com/tchajed/goose/machine"
	"sync"
)

// Key server.

type keyServ struct {
	sk     cryptoFFI.PrivateKey
	mu     *sync.Mutex
	trees  []*merkle.Tree
	nextTr *merkle.Tree
	chain  []linkTy
}

func newKeyServ(sk cryptoFFI.PrivateKey) *keyServ {
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
	var hr cryptoHelpers.Hasher
	cryptoHelpers.HasherWrite(&hr, data)
	cryptoHelpers.HasherWrite(&hr, prevLink)
	newLink := cryptoHelpers.HasherSum(hr, nil)
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
func (s *keyServ) put(id merkle.Id, val merkle.Val) (epochTy, cryptoFFI.Sig, errorTy) {
	s.mu.Lock()
	nextEpoch := uint64(len(s.trees))
	_, _, err := s.nextTr.Put(id, val)
	enc := (&idValEpoch{id: id, val: val, epoch: nextEpoch}).encode()
	sig := cryptoFFI.Sign(s.sk, enc)
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
	sig := cryptoFFI.Sign(s.sk, enc)
	s.mu.Unlock()
	return &getIdAtEpochReply{digest: reply.Digest, proof: reply.Proof,
		sig: sig, error: reply.Error}
}

func (s *keyServ) getIdLatest(id merkle.Id) *getIdLatestReply {
	s.mu.Lock()
	lastEpoch := uint64(len(s.trees)) - 1
	tr := s.trees[lastEpoch]
	reply := tr.Get(id)
	enc := (&epochHash{epoch: lastEpoch, hash: reply.Digest}).encode()
	sig := cryptoFFI.Sign(s.sk, enc)
	s.mu.Unlock()
	return &getIdLatestReply{epoch: lastEpoch, val: reply.Val, digest: reply.Digest,
		proofTy: reply.ProofTy, proof: reply.Proof, sig: sig, error: reply.Error}
}

func (s *keyServ) getDigest(epoch epochTy) (merkle.Digest, cryptoFFI.Sig, errorTy) {
	s.mu.Lock()
	if epoch >= uint64(len(s.trees)) {
		s.mu.Unlock()
		return nil, nil, errSome
	}
	tr := s.trees[epoch]
	dig := tr.Digest()
	enc := (&epochHash{epoch: epoch, hash: dig}).encode()
	sig := cryptoFFI.Sign(s.sk, enc)
	s.mu.Unlock()
	return dig, sig, errNone
}

func (s *keyServ) start(addr grove_ffi.Address) {
	handlers := make(map[uint64]func([]byte, *[]byte))

	handlers[rpcKeyServUpdateEpoch] =
		func(enc_args []byte, enc_reply *[]byte) {
			s.updateEpoch()
		}

	handlers[rpcKeyServPut] =
		func(enc_args []byte, enc_reply *[]byte) {
			args := &putArg{}
			_, err0 := args.decode(enc_args)
			if err0 != errNone {
				*enc_reply = (&putReply{epoch: 0, error: err0}).encode()
				return
			}
			epoch, sig, err1 := s.put(args.id, args.val)
			*enc_reply = (&putReply{epoch: epoch, sig: sig, error: err1}).encode()
		}

	handlers[rpcKeyServGetIdAtEpoch] =
		func(enc_args []byte, enc_reply *[]byte) {
			args := &getIdAtEpochArg{}
			_, err0 := args.decode(enc_args)
			if err0 != errNone {
				reply := &getIdAtEpochReply{}
				reply.error = errSome
				*enc_reply = reply.encode()
				return
			}
			reply := s.getIdAtEpoch(args.id, args.epoch)
			*enc_reply = reply.encode()
		}

	handlers[rpcKeyServGetIdLatest] =
		func(enc_args []byte, enc_reply *[]byte) {
			args := &getIdLatestArg{}
			_, err0 := args.decode(enc_args)
			if err0 != errNone {
				reply := &getIdLatestReply{}
				reply.error = errSome
				*enc_reply = reply.encode()
				return
			}
			reply := s.getIdLatest(args.id)
			*enc_reply = reply.encode()
		}

	handlers[rpcKeyServGetDigest] =
		func(enc_args []byte, enc_reply *[]byte) {
			args := &getDigestArg{}
			_, err0 := args.decode(enc_args)
			if err0 != errNone {
				reply := &getDigestReply{}
				reply.error = errSome
				*enc_reply = reply.encode()
				return
			}
			dig, sig, err1 := s.getDigest(args.epoch)
			*enc_reply = (&getDigestReply{digest: dig, sig: sig, error: err1}).encode()
		}

	urpc.MakeServer(handlers).Serve(addr)
}

// Auditor.

type auditor struct {
	mu     *sync.Mutex
	sk     cryptoFFI.PrivateKey
	servPk cryptoFFI.PublicKey
	chain  []linkTy
}

func newAuditor(sk cryptoFFI.PrivateKey, servPk cryptoFFI.PublicKey) *auditor {
	return &auditor{mu: new(sync.Mutex), sk: sk, servPk: servPk, chain: nil}
}

func (a *auditor) update(epoch epochTy, dig merkle.Digest, sig cryptoFFI.Sig) errorTy {
	a.mu.Lock()
	enc := (&epochHash{epoch: epoch, hash: dig}).encode()
	ok := cryptoFFI.Verify(a.servPk, enc, sig)
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

func (a *auditor) getLink(epoch epochTy) (linkTy, cryptoFFI.Sig, errorTy) {
	a.mu.Lock()
	if epoch >= uint64(len(a.chain)) {
		a.mu.Unlock()
		return nil, nil, errSome
	}
	link := a.chain[epoch]
	enc := (&epochHash{epoch: epoch, hash: link}).encode()
	sig := cryptoFFI.Sign(a.sk, enc)
	a.mu.Unlock()
	return link, sig, errNone
}

func (a *auditor) start(addr grove_ffi.Address) {
	handlers := make(map[uint64]func([]byte, *[]byte))

	handlers[rpcAuditorUpdate] =
		func(enc_args []byte, enc_reply *[]byte) {
			args := &updateArg{}
			_, err0 := args.decode(enc_args)
			if err0 != errNone {
				reply := &updateReply{}
				reply.error = errSome
				*enc_reply = reply.encode()
				return
			}
			err1 := a.update(args.epoch, args.digest, args.sig)
			*enc_reply = (&updateReply{error: err1}).encode()
		}

	handlers[rpcAuditorGetLink] =
		func(enc_args []byte, enc_reply *[]byte) {
			args := &getLinkArg{}
			_, err0 := args.decode(enc_args)
			if err0 != errNone {
				reply := &getLinkReply{}
				reply.error = errSome
				*enc_reply = reply.encode()
				return
			}
			link, sig, err1 := a.getLink(args.epoch)
			*enc_reply = (&getLinkReply{link: link, sig: sig, error: err1}).encode()
		}

	urpc.MakeServer(handlers).Serve(addr)
}

// Key client.

type keyCli struct {
	adtrs     []*urpc.Client
	adtrPks   []cryptoFFI.PublicKey
	servPk    cryptoFFI.PublicKey
	digs      map[epochTy]merkle.Digest
	id        merkle.Id
	serv      *urpc.Client
	valEpochs []epochTy
	vals      []merkle.Val
}

func newKeyCli(id merkle.Id, servAddr grove_ffi.Address, adtrAddrs []grove_ffi.Address, adtrPks []cryptoFFI.PublicKey, servPk cryptoFFI.PublicKey) *keyCli {
	c := &keyCli{}
	c.serv = urpc.MakeClient(servAddr)
	var adtrs []*urpc.Client
	for _, addr := range adtrAddrs {
		adtrs = append(adtrs, urpc.MakeClient(addr))
	}
	c.adtrs = adtrs
	c.adtrPks = adtrPks
	c.servPk = servPk
	c.digs = make(map[epochTy]merkle.Digest)
	c.id = id
	return c
}

// TODO: what happens if client calls put twice in an epoch?
func (c *keyCli) put(val merkle.Val) (epochTy, errorTy) {
	epoch, sig, err := callPut(c.serv, c.id, val)
	if err != errNone {
		return 0, err
	}
	enc := (&idValEpoch{id: c.id, val: val, epoch: epoch}).encode()
	ok := cryptoFFI.Verify(c.servPk, enc, sig)
	if !ok {
		return 0, errSome
	}
	c.valEpochs = append(c.valEpochs, epoch)
	c.vals = append(c.vals, val)
	return epoch, errNone
}

func (c *keyCli) get(id merkle.Id) (epochTy, merkle.Val, errorTy) {
	reply := callGetIdLatest(c.serv, id)
	epoch := reply.epoch
	val := reply.val
	dig := reply.digest
	proofTy := reply.proofTy
	proof := reply.proof
	sig := reply.sig
	err0 := reply.error
	if err0 != errNone {
		return 0, nil, err0
	}

	enc := (&epochHash{epoch: epoch, hash: dig}).encode()
	ok0 := cryptoFFI.Verify(c.servPk, enc, sig)
	if !ok0 {
		return 0, nil, errSome
	}

	err1 := merkle.CheckProof(proofTy, proof, id, val, dig)
	if err1 != errNone {
		return 0, nil, err1
	}

	// If we don't have dig, add it. Otherwise, compare against what we have.
	origDig, ok1 := c.digs[epoch]
	var err2 errorTy
	if ok1 {
		if !std.BytesEqual(origDig, dig) {
			err2 = errSome
		}
	} else {
		c.digs[epoch] = dig
	}
	return epoch, val, err2
}

func (c *keyCli) getOrFillDig(epoch epochTy) (merkle.Digest, errorTy) {
	var dig merkle.Digest
	dig, ok0 := c.digs[epoch]
	if ok0 {
		return dig, errNone
	}
	newDig, sig, err := callGetDigest(c.serv, epoch)
	if err != errNone {
		return nil, err
	}
	enc := (&epochHash{epoch: epoch, hash: newDig}).encode()
	ok1 := cryptoFFI.Verify(c.servPk, enc, sig)
	if !ok1 {
		return nil, errSome
	}
	c.digs[epoch] = newDig
	return newDig, errNone
}

// Audited through Epoch idx in retval.
func (c *keyCli) audit(adtrId uint64) (epochTy, errorTy) {
	// Note: potential attack.
	// Key serv refuses to fill in a hole, even though we have bigger digests.
	var link linkTy
	var epoch uint64
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
	epoch--

	adtr := c.adtrs[adtrId]
	adtrPk := c.adtrPks[adtrId]
	adtrLink, sig, err1 := callGetLink(adtr, epoch)
	if err1 != errNone {
		return 0, err1
	}

	enc := (&epochHash{epoch: epoch, hash: link}).encode()
	ok := cryptoFFI.Verify(adtrPk, enc, sig)
	if !ok {
		return 0, errSome
	}
	if !std.BytesEqual(link, adtrLink) {
		return 0, errSome
	}

	return epoch, errNone
}

func (c *keyCli) checkProofWithExpected(epoch epochTy, val merkle.Val, proofTy merkle.ProofTy) okTy {
	id := c.id
	reply := callGetIdAtEpoch(c.serv, id, epoch)
	dig := reply.digest
	proof := reply.proof
	sig := reply.sig
	err0 := reply.error
	if err0 != errNone {
		return false
	}
	enc := (&epochHash{epoch: epoch, hash: dig}).encode()
	ok0 := cryptoFFI.Verify(c.servPk, enc, sig)
	if !ok0 {
		return false
	}
	// There will only be one (proofTy, val) pair that will
	// injectively satisfy the (id, dig), so don't need
	// to request them from the server.
	err1 := merkle.CheckProof(proofTy, proof, id, val, dig)
	if err1 != errNone {
		return false
	}
	// Compare the dig against what we already might have.
	origDig, ok1 := c.digs[epoch]
	if ok1 && !std.BytesEqual(dig, origDig) {
		return false
	}
	if !ok1 {
		c.digs[epoch] = dig
	}
	return true
}

// Audited through retval Epoch idx exclusive.
// TODO: we use inclusive in other places.
// make sure we're not doing anything stupid.
func (c *keyCli) selfAudit() epochTy {
	numVals := uint64(len(c.vals))
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

func testAgreement(servAddr, adtrAddr grove_ffi.Address) {
	servSk, servPk := cryptoFFI.MakeKeys()
	go func() {
		s := newKeyServ(servSk)
		s.start(servAddr)
	}()

	adtrSk, adtrPk := cryptoFFI.MakeKeys()
	adtrPks := []cryptoFFI.PublicKey{adtrPk}
	adtrAddrs := []grove_ffi.Address{adtrAddr}
	go func() {
		a := newAuditor(adtrSk, servPk)
		a.start(adtrAddr)
	}()

	machine.Sleep(1_000_000)
	servCli := urpc.MakeClient(servAddr)
	adtrCli := urpc.MakeClient(adtrAddr)

	aliceId := cryptoFFI.Hash([]byte("alice"))
	aliceVal := []byte("val")
	aliceCli := newKeyCli(aliceId, servAddr, adtrAddrs, adtrPks, servPk)
	_, err0 := aliceCli.put(aliceVal)
	machine.Assume(err0 == errNone)

	emptyReplyB := make([]byte, 0)
	err1 := servCli.Call(rpcKeyServUpdateEpoch, nil, &emptyReplyB, 100)
	machine.Assume(err1 == urpc.ErrNone)

	epochAdtr := updateAdtrDigs(servCli, adtrCli)
	machine.Assume(epochAdtr == uint64(2))

	bobId := cryptoFFI.Hash([]byte("bob"))
	bobCli := newKeyCli(bobId, servAddr, adtrAddrs, adtrPks, servPk)
	charlieId := cryptoFFI.Hash([]byte("charlie"))
	charlieCli := newKeyCli(charlieId, servAddr, adtrAddrs, adtrPks, servPk)

	epoch0, val0, err3 := bobCli.get(aliceId)
	machine.Assume(err3 == errNone)
	epoch1, val1, err4 := charlieCli.get(aliceId)
	machine.Assume(err4 == errNone)

	epoch2, err5 := bobCli.audit(0)
	machine.Assume(err5 == errNone)
	epoch3, err6 := charlieCli.audit(0)
	machine.Assume(err6 == errNone)

	if epoch0 == epoch1 && epoch0 <= epoch2 && epoch1 <= epoch3 {
		machine.Assert(std.BytesEqual(val0, val1))
	}
}
