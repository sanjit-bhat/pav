package ktMerkle

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/secure-chat/cryptoHelpers"
	"github.com/mit-pdos/secure-chat/cryptoShim"
	"github.com/mit-pdos/secure-chat/merkle"
	"sync"
)

// Key server.

type KeyServ struct {
	Mu     *sync.Mutex
	Trees  []*merkle.Tree
	NextTr *merkle.Tree
	Chain  []Link
}

func NewKeyServ() *KeyServ {
	s := &KeyServ{}
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

func (s *KeyServ) Put(id merkle.Id, val merkle.Val) (Epoch, Error) {
	s.Mu.Lock()
	nextEpoch := uint64(len(s.Trees))
	_, _, err := s.NextTr.Put(id, val)
	s.Mu.Unlock()
	return nextEpoch, err
}

func (s *KeyServ) GetIdAtEpoch(id merkle.Id, epoch Epoch) *GetIdAtEpochReply {
	errReply := &GetIdAtEpochReply{}
	s.Mu.Lock()
	if epoch >= uint64(len(s.Trees)) {
		s.Mu.Unlock()
		errReply.Error = ErrSome
		return errReply
	}
	tr := s.Trees[epoch]
	reply := tr.Get(id)
	s.Mu.Unlock()
	return &GetIdAtEpochReply{Val: reply.Val, Digest: reply.Digest,
		ProofTy: reply.ProofTy, Proof: reply.Proof, Error: reply.Error}
}

func (s *KeyServ) GetIdLatest(id merkle.Id) *GetIdLatestReply {
	s.Mu.Lock()
	lastEpoch := uint64(len(s.Trees)) - 1
	tr := s.Trees[lastEpoch]
	reply := tr.Get(id)
	s.Mu.Unlock()
	return &GetIdLatestReply{Epoch: lastEpoch, Val: reply.Val, Digest: reply.Digest,
		ProofTy: reply.ProofTy, Proof: reply.Proof, Error: reply.Error}
}

func (s *KeyServ) GetDigest(epoch Epoch) (merkle.Digest, Error) {
	s.Mu.Lock()
	if epoch >= uint64(len(s.Trees)) {
		s.Mu.Unlock()
		return nil, ErrSome
	}
	tr := s.Trees[epoch]
	dig := tr.Digest()
	s.Mu.Unlock()
	return dig, ErrNone
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
			epoch, err1 := s.Put(args.Id, args.Val)
			*enc_reply = (&PutReply{Epoch: epoch, Error: err1}).Encode()
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
			dig, err1 := s.GetDigest(args.Epoch)
			*enc_reply = (&GetDigestReply{Digest: dig, Error: err1}).Encode()
		}

	urpc.MakeServer(handlers).Serve(addr)
}

// Auditor.

type Auditor struct {
	Mu    *sync.Mutex
	Sk    cryptoShim.SignerT
	Chain []Link
}

func NewAuditor(sk cryptoShim.SignerT) *Auditor {
	return &Auditor{Mu: new(sync.Mutex), Sk: sk, Chain: nil}
}

func (a *Auditor) Update(dig merkle.Digest) {
	a.Mu.Lock()
	ExtendChain(&a.Chain, dig)
	a.Mu.Unlock()
}

func (a *Auditor) GetLink(epoch Epoch) (Link, cryptoShim.Sig, Error) {
	a.Mu.Lock()
	if epoch >= uint64(len(a.Chain)) {
		a.Mu.Unlock()
		return nil, nil, ErrSome
	}
	link := a.Chain[epoch]
	encB := (&EpochHash{Epoch: epoch, Hash: link}).Encode()
	sig := cryptoShim.Sign(a.Sk, encB)
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
			a.Update(args.Digest)
			*enc_reply = (&UpdateReply{Error: ErrNone}).Encode()
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
	Digs      map[Epoch]merkle.Digest
	Id        merkle.Id
	Serv      *urpc.Client
	ValEpochs []Epoch
	Vals      []merkle.Val
}

func NewKeyCli(id merkle.Id, servAddr grove_ffi.Address, adtrAddrs []grove_ffi.Address, adtrVks []cryptoShim.VerifierT) *KeyCli {
	c := &KeyCli{}
	c.Serv = urpc.MakeClient(servAddr)
	var adtrs []*urpc.Client
	for _, addr := range adtrAddrs {
		adtrs = append(adtrs, urpc.MakeClient(addr))
	}
	c.Adtrs = adtrs
	c.AdtrVks = adtrVks
	c.Digs = make(map[Epoch]merkle.Digest)
	c.Id = id
	return c
}

// TODO: what happens if client calls Put twice in an epoch?
func (c *KeyCli) Put(val merkle.Val) Error {
	epoch, err := CallPut(c.Serv, c.Id, val)
	if err != ErrNone {
		return err
	}
	c.ValEpochs = append(c.ValEpochs, epoch)
	c.Vals = append(c.Vals, val)
	return ErrNone
}

func (c *KeyCli) Get(id merkle.Id) (merkle.Val, Error) {
	reply := CallGetIdLatest(c.Serv, id)
	epoch := reply.Epoch
	val := reply.Val
	dig := reply.Digest
	err0 := reply.Error
	if err0 != ErrNone {
		return nil, err0
	}

	err1 := merkle.CheckProof(reply.ProofTy, reply.Proof, id, val, dig)
	if err1 != ErrNone {
		return nil, err1
	}

	// If we don't have dig, add it. Otherwise, compare against what we have.
	origDig, ok := c.Digs[epoch]
	var err2 Error
	if ok {
		if !std.BytesEqual(origDig, dig) {
			err2 = ErrSome
		}
	} else {
		c.Digs[epoch] = dig
	}
	return val, err2
}

// Audited through Epoch idx in retval.
func (c *KeyCli) Audit(adtrId uint64) (Epoch, Error) {
	// Note: potential attack.
	// Key serv refuses to fill in a hole, even though we have bigger digests.
	var link Link
	var epoch uint64
	var stop bool
	// Loop written in weird way bc Goose doesn't support continue in nested Ifs.
	for !stop {
		var dig merkle.Digest
		dig, ok0 := c.Digs[epoch]
		if !ok0 {
			newDig, err0 := CallGetDigest(c.Serv, epoch)
			if err0 != ErrNone {
				stop = true
			} else {
				c.Digs[epoch] = newDig
				dig = newDig
			}
		}
		if !stop {
			link = CalcNextLink(link, dig)
			epoch++
		}
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

	encB := (&EpochHash{Epoch: epoch, Hash: link}).Encode()
	ok1 := cryptoShim.Verify(adtrVk, encB, sig)
	if !ok1 {
		return 0, ErrSome
	}
	if !std.BytesEqual(link, adtrLink) {
		return 0, ErrSome
	}

	return epoch, ErrNone
}

// Audited through Epoch idx in retval.
func (c *KeyCli) SelfAudit() (Epoch, Error) {
	id := c.Id
	numVals := uint64(len(c.Vals))
	var valIdx uint64
	var epoch Epoch
	var stop bool
	for !stop {
		// Check if we hit val at the next epoch.
		if valIdx != numVals {
			epochChange := c.ValEpochs[valIdx]
			if epoch == epochChange {
				valIdx++
			}
		}
		var expProofTy merkle.ProofTy
		var expVal merkle.Val
		// Check if we're before we even put a val.
		if valIdx != 0 {
			expProofTy = merkle.MembProofTy
			expVal = c.Vals[valIdx-1]
		}

		reply := CallGetIdAtEpoch(c.Serv, id, epoch)
		dig := reply.Digest
		err0 := reply.Error
		if err0 != ErrNone {
			stop = true
			continue
		}
		if reply.ProofTy != expProofTy {
			stop = true
			continue
		}
		err1 := merkle.CheckProof(reply.ProofTy, reply.Proof, id, expVal, dig)
		if err1 != ErrNone {
			stop = true
			continue
		}
		// Store the dig if we don't already have it.
		origDig, ok0 := c.Digs[epoch]
		if !ok0 {
			c.Digs[epoch] = dig
		} else if !std.BytesEqual(dig, origDig) {
			stop = true
		}
		if !stop {
			epoch++
		}
	}
	if epoch == 0 {
		return 0, ErrSome
	}
	epoch--
	return epoch, ErrNone
}
