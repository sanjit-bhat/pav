package ktMerkle

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/secure-chat/cryptoHelpers"
	"github.com/mit-pdos/secure-chat/cryptoShim"
	"github.com/mit-pdos/secure-chat/merkle"
	"github.com/tchajed/goose/machine"
	"sync"
)

// Key server.

type KeyServ struct {
	Sk     cryptoShim.SignerT
	Mu     *sync.Mutex
	Trees  []*merkle.Tree
	NextTr *merkle.Tree
	Chain  []Link
}

func NewKeyServ(sk cryptoShim.SignerT) *KeyServ {
	s := &KeyServ{}
	s.Sk = sk
	s.Mu = new(sync.Mutex)
	emptyTr := &merkle.Tree{}
	s.Trees = []*merkle.Tree{emptyTr}
	s.NextTr = &merkle.Tree{}
	s.Chain = []Link{emptyTr.Digest()}
	return s
}

func CalcNextLink(prevLink Link, data []byte) Link {
	var hr cryptoHelpers.Hasher
	cryptoHelpers.HasherWrite(&hr, data)
	cryptoHelpers.HasherWrite(&hr, prevLink)
	newLink := cryptoHelpers.HasherSum(hr, nil)
	return newLink
}

func ExtendChain(chain *[]Link, data []byte) {
	oldChain := *chain
	var prevLink Link
	chainLen := uint64(len(oldChain))
	if chainLen > 0 {
		prevLink = oldChain[chainLen-1]
	}
	newLink := CalcNextLink(prevLink, data)
	*chain = append(oldChain, newLink)
}

func (s *KeyServ) UpdateEpoch() {
	s.Mu.Lock()
	nextTr := s.NextTr
	dig := nextTr.Digest()
	ExtendChain(&s.Chain, dig)
	s.Trees = append(s.Trees, nextTr)
	s.NextTr = nextTr.DeepCopy()
	s.Mu.Unlock()
}

func (s *KeyServ) Put(id merkle.Id, val merkle.Val) (Epoch, cryptoShim.Sig, Error) {
	s.Mu.Lock()
	nextEpoch := uint64(len(s.Trees))
	_, _, err := s.NextTr.Put(id, val)
	enc := (&IdValEpoch{Id: id, Val: val, Epoch: nextEpoch}).Encode()
	sig := cryptoShim.Sign(s.Sk, enc)
	s.Mu.Unlock()
	return nextEpoch, sig, err
}

func (s *KeyServ) GetIdAtEpoch(id merkle.Id, epoch Epoch) *GetIdAtEpochReply {
	errReply := &GetIdAtEpochReply{}
	errReply.Error = ErrSome
	s.Mu.Lock()
	if epoch >= uint64(len(s.Trees)) {
		s.Mu.Unlock()
		return errReply
	}
	tr := s.Trees[epoch]
	reply := tr.Get(id)
	enc := (&EpochHash{Epoch: epoch, Hash: reply.Digest}).Encode()
	sig := cryptoShim.Sign(s.Sk, enc)
	s.Mu.Unlock()
	return &GetIdAtEpochReply{Digest: reply.Digest, Proof: reply.Proof,
		Sig: sig, Error: reply.Error}
}

func (s *KeyServ) GetIdLatest(id merkle.Id) *GetIdLatestReply {
	s.Mu.Lock()
	lastEpoch := uint64(len(s.Trees)) - 1
	tr := s.Trees[lastEpoch]
	reply := tr.Get(id)
	enc := (&EpochHash{Epoch: lastEpoch, Hash: reply.Digest}).Encode()
	sig := cryptoShim.Sign(s.Sk, enc)
	s.Mu.Unlock()
	return &GetIdLatestReply{Epoch: lastEpoch, Val: reply.Val, Digest: reply.Digest,
		ProofTy: reply.ProofTy, Proof: reply.Proof, Sig: sig, Error: reply.Error}
}

func (s *KeyServ) GetDigest(epoch Epoch) (merkle.Digest, cryptoShim.Sig, Error) {
	s.Mu.Lock()
	if epoch >= uint64(len(s.Trees)) {
		s.Mu.Unlock()
		return nil, nil, ErrSome
	}
	tr := s.Trees[epoch]
	dig := tr.Digest()
	enc := (&EpochHash{Epoch: epoch, Hash: dig}).Encode()
	sig := cryptoShim.Sign(s.Sk, enc)
	s.Mu.Unlock()
	return dig, sig, ErrNone
}

func (s *KeyServ) Start(addr grove_ffi.Address) {
	handlers := make(map[uint64]func([]byte, *[]byte))

	handlers[RpcKeyServUpdateEpoch] =
		func(enc_args []byte, enc_reply *[]byte) {
			s.UpdateEpoch()
		}

	handlers[RpcKeyServPut] =
		func(enc_args []byte, enc_reply *[]byte) {
			args := &PutArg{}
			_, err0 := args.Decode(enc_args)
			if err0 != ErrNone {
				*enc_reply = (&PutReply{Epoch: 0, Error: err0}).Encode()
				return
			}
			epoch, sig, err1 := s.Put(args.Id, args.Val)
			*enc_reply = (&PutReply{Epoch: epoch, Sig: sig, Error: err1}).Encode()
		}

	handlers[RpcKeyServGetIdAtEpoch] =
		func(enc_args []byte, enc_reply *[]byte) {
			args := &GetIdAtEpochArg{}
			_, err0 := args.Decode(enc_args)
			if err0 != ErrNone {
				reply := &GetIdAtEpochReply{}
				reply.Error = ErrSome
				*enc_reply = reply.Encode()
				return
			}
			reply := s.GetIdAtEpoch(args.Id, args.Epoch)
			*enc_reply = reply.Encode()
		}

	handlers[RpcKeyServGetIdLatest] =
		func(enc_args []byte, enc_reply *[]byte) {
			args := &GetIdLatestArg{}
			_, err0 := args.Decode(enc_args)
			if err0 != ErrNone {
				reply := &GetIdLatestReply{}
				reply.Error = ErrSome
				*enc_reply = reply.Encode()
				return
			}
			reply := s.GetIdLatest(args.Id)
			*enc_reply = reply.Encode()
		}

	handlers[RpcKeyServGetDigest] =
		func(enc_args []byte, enc_reply *[]byte) {
			args := &GetDigestArg{}
			_, err0 := args.Decode(enc_args)
			if err0 != ErrNone {
				reply := &GetDigestReply{}
				reply.Error = ErrSome
				*enc_reply = reply.Encode()
				return
			}
			dig, sig, err1 := s.GetDigest(args.Epoch)
			*enc_reply = (&GetDigestReply{Digest: dig, Sig: sig, Error: err1}).Encode()
		}

	urpc.MakeServer(handlers).Serve(addr)
}

// Auditor.

type Auditor struct {
	Mu     *sync.Mutex
	Sk     cryptoShim.SignerT
	ServVk cryptoShim.VerifierT
	Chain  []Link
}

func NewAuditor(sk cryptoShim.SignerT, servVk cryptoShim.VerifierT) *Auditor {
	return &Auditor{Mu: new(sync.Mutex), Sk: sk, ServVk: servVk, Chain: nil}
}

func (a *Auditor) Update(epoch Epoch, dig merkle.Digest, sig cryptoShim.Sig) Error {
	a.Mu.Lock()
	enc := (&EpochHash{Epoch: epoch, Hash: dig}).Encode()
	ok := cryptoShim.Verify(a.ServVk, enc, sig)
	if !ok {
		a.Mu.Unlock()
		return ErrSome
	}
	if epoch != uint64(len(a.Chain)) {
		a.Mu.Unlock()
		return ErrSome
	}
	ExtendChain(&a.Chain, dig)
	a.Mu.Unlock()
	return ErrNone
}

func (a *Auditor) GetLink(epoch Epoch) (Link, cryptoShim.Sig, Error) {
	a.Mu.Lock()
	if epoch >= uint64(len(a.Chain)) {
		a.Mu.Unlock()
		return nil, nil, ErrSome
	}
	link := a.Chain[epoch]
	enc := (&EpochHash{Epoch: epoch, Hash: link}).Encode()
	sig := cryptoShim.Sign(a.Sk, enc)
	a.Mu.Unlock()
	return link, sig, ErrNone
}

func (a *Auditor) Start(addr grove_ffi.Address) {
	handlers := make(map[uint64]func([]byte, *[]byte))

	handlers[RpcAuditorUpdate] =
		func(enc_args []byte, enc_reply *[]byte) {
			args := &UpdateArg{}
			_, err0 := args.Decode(enc_args)
			if err0 != ErrNone {
				reply := &UpdateReply{}
				reply.Error = ErrSome
				*enc_reply = reply.Encode()
				return
			}
			err1 := a.Update(args.Epoch, args.Digest, args.Sig)
			*enc_reply = (&UpdateReply{Error: err1}).Encode()
		}

	handlers[RpcAuditorGetLink] =
		func(enc_args []byte, enc_reply *[]byte) {
			args := &GetLinkArg{}
			_, err0 := args.Decode(enc_args)
			if err0 != ErrNone {
				reply := &GetLinkReply{}
				reply.Error = ErrSome
				*enc_reply = reply.Encode()
				return
			}
			link, sig, err1 := a.GetLink(args.Epoch)
			*enc_reply = (&GetLinkReply{Link: link, Sig: sig, Error: err1}).Encode()
		}

	urpc.MakeServer(handlers).Serve(addr)
}

// Key client.

type KeyCli struct {
	Adtrs     []*urpc.Client
	AdtrVks   []cryptoShim.VerifierT
	ServVk    cryptoShim.VerifierT
	Digs      map[Epoch]merkle.Digest
	Id        merkle.Id
	Serv      *urpc.Client
	ValEpochs []Epoch
	Vals      []merkle.Val
}

func NewKeyCli(id merkle.Id, servAddr grove_ffi.Address, adtrAddrs []grove_ffi.Address, adtrVks []cryptoShim.VerifierT, servVk cryptoShim.VerifierT) *KeyCli {
	c := &KeyCli{}
	c.Serv = urpc.MakeClient(servAddr)
	var adtrs []*urpc.Client
	for _, addr := range adtrAddrs {
		adtrs = append(adtrs, urpc.MakeClient(addr))
	}
	c.Adtrs = adtrs
	c.AdtrVks = adtrVks
	c.ServVk = servVk
	c.Digs = make(map[Epoch]merkle.Digest)
	c.Id = id
	return c
}

// TODO: what happens if client calls Put twice in an epoch?
func (c *KeyCli) Put(val merkle.Val) Error {
	epoch, sig, err := CallPut(c.Serv, c.Id, val)
	if err != ErrNone {
		return err
	}
	enc := (&IdValEpoch{Id: c.Id, Val: val, Epoch: epoch}).Encode()
	ok := cryptoShim.Verify(c.ServVk, enc, sig)
	if !ok {
		return ErrSome
	}
	c.ValEpochs = append(c.ValEpochs, epoch)
	c.Vals = append(c.Vals, val)
	return ErrNone
}

func (c *KeyCli) Get(id merkle.Id) (Epoch, merkle.Val, Error) {
	reply := CallGetIdLatest(c.Serv, id)
	epoch := reply.Epoch
	val := reply.Val
	dig := reply.Digest
	proofTy := reply.ProofTy
	proof := reply.Proof
	sig := reply.Sig
	err0 := reply.Error
	if err0 != ErrNone {
		return 0, nil, err0
	}

	enc := (&EpochHash{Epoch: epoch, Hash: dig}).Encode()
	ok0 := cryptoShim.Verify(c.ServVk, enc, sig)
	if !ok0 {
		return 0, nil, ErrSome
	}

	err1 := merkle.CheckProof(proofTy, proof, id, val, dig)
	if err1 != ErrNone {
		return 0, nil, err1
	}

	// If we don't have dig, add it. Otherwise, compare against what we have.
	origDig, ok1 := c.Digs[epoch]
	var err2 Error
	if ok1 {
		if !std.BytesEqual(origDig, dig) {
			err2 = ErrSome
		}
	} else {
		c.Digs[epoch] = dig
	}
	return epoch, val, err2
}

func (c *KeyCli) getOrFillDig(epoch Epoch) (merkle.Digest, Error) {
	var dig merkle.Digest
	dig, ok0 := c.Digs[epoch]
	if ok0 {
		return dig, ErrNone
	}
	newDig, sig, err := CallGetDigest(c.Serv, epoch)
	if err != ErrNone {
		return nil, err
	}
	enc := (&EpochHash{Epoch: epoch, Hash: newDig}).Encode()
	ok1 := cryptoShim.Verify(c.ServVk, enc, sig)
	if !ok1 {
		return nil, ErrSome
	}
	c.Digs[epoch] = newDig
	return newDig, ErrNone
}

// Audited through Epoch idx in retval.
func (c *KeyCli) Audit(adtrId uint64) (Epoch, Error) {
	// Note: potential attack.
	// Key serv refuses to fill in a hole, even though we have bigger digests.
	var link Link
	var epoch uint64
	for {
		dig, err0 := c.getOrFillDig(epoch)
		if err0 != ErrNone {
			break
		}
		link = CalcNextLink(link, dig)
		epoch++
	}
	if epoch == 0 {
		return 0, ErrSome
	}
	epoch--

	adtr := c.Adtrs[adtrId]
	adtrVk := c.AdtrVks[adtrId]
	adtrLink, sig, err1 := CallGetLink(adtr, epoch)
	if err1 != ErrNone {
		return 0, err1
	}

	enc := (&EpochHash{Epoch: epoch, Hash: link}).Encode()
	ok := cryptoShim.Verify(adtrVk, enc, sig)
	if !ok {
		return 0, ErrSome
	}
	if !std.BytesEqual(link, adtrLink) {
		return 0, ErrSome
	}

	return epoch, ErrNone
}

func (c *KeyCli) checkProofWithExpected(epoch Epoch, val merkle.Val, proofTy merkle.ProofTy) Ok {
	id := c.Id
	reply := CallGetIdAtEpoch(c.Serv, id, epoch)
	dig := reply.Digest
	proof := reply.Proof
	sig := reply.Sig
	err0 := reply.Error
	if err0 != ErrNone {
		return false
	}
	enc := (&EpochHash{Epoch: epoch, Hash: dig}).Encode()
	ok0 := cryptoShim.Verify(c.ServVk, enc, sig)
	if !ok0 {
		return false
	}
	// There will only be one (proofTy, val) pair that will
	// injectively satisfy the (id, dig), so don't need
	// to request them from the server.
	err1 := merkle.CheckProof(proofTy, proof, id, val, dig)
	if err1 != ErrNone {
		return false
	}
	// Compare the dig against what we already might have.
	origDig, ok1 := c.Digs[epoch]
	if ok1 && !std.BytesEqual(dig, origDig) {
		return false
	}
	if !ok1 {
		c.Digs[epoch] = dig
	}
	return true
}

// Audited through retval Epoch idx exclusive.
// TODO: we use inclusive in other places.
// make sure we're not doing anything stupid.
func (c *KeyCli) SelfAudit() Epoch {
	numVals := uint64(len(c.Vals))
	var valIdx uint64
	var epoch Epoch
	for {
		// Check if we're at the next val update.
		if valIdx != numVals {
			epochChange := c.ValEpochs[valIdx]
			if epoch == epochChange {
				valIdx++
			}
		}
		var expProofTy merkle.ProofTy
		var expVal merkle.Val
		// Check if at epoch before we even sent a val.
		if valIdx != 0 {
			expProofTy = merkle.MembProofTy
			expVal = c.Vals[valIdx-1]
		}
		ok := c.checkProofWithExpected(epoch, expVal, expProofTy)
		if !ok {
			break
		}
		epoch++
	}
	return epoch
}

func UpdateAdtrDigs(servCli, adtrCli *urpc.Client) Epoch {
	var epoch uint64 = 0
	for {
		dig, sig, err0 := CallGetDigest(servCli, epoch)
		if err0 != ErrNone {
			break
		}
		err1 := CallUpdate(adtrCli, epoch, dig, sig)
		if err1 != ErrNone {
			break
		}
		epoch++
	}
	return epoch
}

func testAgreement(servAddr, adtrAddr grove_ffi.Address) {
	servSk, servVk := cryptoShim.MakeKeys()
	go func() {
		s := NewKeyServ(servSk)
		s.Start(servAddr)
	}()

	adtrSk, adtrVk := cryptoShim.MakeKeys()
	adtrVks := []cryptoShim.VerifierT{adtrVk}
	adtrAddrs := []grove_ffi.Address{adtrAddr}
	go func() {
		a := NewAuditor(adtrSk, servVk)
		a.Start(adtrAddr)
	}()

	machine.Sleep(1_000_000)
	servCli := urpc.MakeClient(servAddr)
	adtrCli := urpc.MakeClient(adtrAddr)

	aliceId := cryptoShim.Hash([]byte("alice"))
	aliceVal := []byte("val")
	aliceCli := NewKeyCli(aliceId, servAddr, adtrAddrs, adtrVks, servVk)
	err0 := aliceCli.Put(aliceVal)
	machine.Assume(err0 == ErrNone)

	emptyReplyB := make([]byte, 0)
	err1 := servCli.Call(RpcKeyServUpdateEpoch, nil, &emptyReplyB, 100)
	machine.Assume(err1 == ErrNone)

	epochAdtr := UpdateAdtrDigs(servCli, adtrCli)
	machine.Assume(epochAdtr == uint64(2))

	bobId := cryptoShim.Hash([]byte("bob"))
	bobCli := NewKeyCli(bobId, servAddr, adtrAddrs, adtrVks, servVk)
	charlieId := cryptoShim.Hash([]byte("charlie"))
	charlieCli := NewKeyCli(charlieId, servAddr, adtrAddrs, adtrVks, servVk)

	epoch0, val0, err3 := bobCli.Get(aliceId)
	machine.Assume(err3 == ErrNone)
	epoch1, val1, err4 := charlieCli.Get(aliceId)
	machine.Assume(err4 == ErrNone)

	epoch2, err5 := bobCli.Audit(0)
	machine.Assume(err5 == ErrNone)
	epoch3, err6 := charlieCli.Audit(0)
	machine.Assume(err6 == ErrNone)

	if epoch0 == epoch1 && epoch0 <= epoch2 && epoch1 <= epoch3 {
		machine.Assert(std.BytesEqual(val0, val1))
	}
}
