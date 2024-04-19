package ktMerkle

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/secure-chat/crypto/helpers"
	"github.com/mit-pdos/secure-chat/crypto/shim"
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
	s.NextTr = &merkle.Tree{}
	return s
}

func CalcNextLink(prevLink Link, data []byte) Link {
	var hr helpers.Hasher
	helpers.HasherWrite(&hr, data)
	helpers.HasherWrite(&hr, prevLink)
	newLink := helpers.HasherSum(hr, nil)
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

func (s *KeyServ) GetIdAtEpoch(id merkle.Id, epoch Epoch) (merkle.Val, merkle.Digest, merkle.ProofTy, merkle.GenProof, Error) {
	s.Mu.Lock()
	if epoch >= uint64(len(s.Trees)) {
		s.Mu.Unlock()
		return nil, nil, false, nil, ErrSome
	}
	tr := s.Trees[epoch]
	val, dig, proofT, proof, err := tr.GetTotal(id)
	s.Mu.Unlock()
	return val, dig, proofT, proof, err
}

func (s *KeyServ) GetIdLatest(id merkle.Id) (Epoch, merkle.Val, merkle.Digest, merkle.ProofTy, merkle.GenProof, Error) {
	s.Mu.Lock()
	numEpochs := uint64(len(s.Trees))
	if numEpochs == 0 {
		s.Mu.Unlock()
		return 0, nil, nil, false, nil, ErrSome
	}
	lastEpoch := numEpochs - 1
	tr := s.Trees[lastEpoch]
	val, dig, proofT, proof, err := tr.GetTotal(id)
	s.Mu.Unlock()
	return lastEpoch, val, dig, proofT, proof, err
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

// Auditor.

type Auditor struct {
	Mu    *sync.Mutex
	Sk    shim.SignerT
	Chain []Link
}

func NewAuditor(sk shim.SignerT) *Auditor {
	return &Auditor{Mu: new(sync.Mutex), Sk: sk, Chain: nil}
}

func (a *Auditor) Update(dig merkle.Digest) {
	a.Mu.Lock()
	ExtendChain(&a.Chain, dig)
	a.Mu.Unlock()
}

// TODO: signing is a bit funky right now, since it's written w/o RPCs.
func (a *Auditor) GetLink(epoch Epoch) (Link, shim.Sig, Error) {
	a.Mu.Lock()
	if epoch >= uint64(len(a.Chain)) {
		a.Mu.Unlock()
		return nil, nil, ErrSome
	}
	link := a.Chain[epoch]
	encB := (&EpochHash{Epoch: epoch, Hash: link}).Encode()
	sig := shim.Sign(a.Sk, encB)
	a.Mu.Unlock()
	return link, sig, ErrNone
}

// Key client.

type KeyCli struct {
	Adtrs     []*Auditor
	AdtrVks   []shim.VerifierT
	Digs      map[Epoch]merkle.Digest
	Id        merkle.Id
	Serv      *KeyServ
	ValEpochs []Epoch
	Vals      []merkle.Val
}

func NewKeyCli(id merkle.Id, serv *KeyServ, adtrs []*Auditor, adtrVks []shim.VerifierT) *KeyCli {
	c := &KeyCli{}
	c.Adtrs = adtrs
	c.AdtrVks = adtrVks
	c.Digs = make(map[Epoch]merkle.Digest)
	c.Id = id
	c.Serv = serv
	return c
}

// TODO: what happens if client calls Put twice in an epoch?
func (c *KeyCli) Put(val merkle.Val) Error {
	epoch, err := c.Serv.Put(c.Id, val)
	if err != ErrNone {
		return err
	}
	c.ValEpochs = append(c.ValEpochs, epoch)
	c.Vals = append(c.Vals, val)
	return ErrNone
}

func (c *KeyCli) Get(id merkle.Id) (merkle.Val, Error) {
	epoch, val, dig, proofTy, proof, err0 := c.Serv.GetIdLatest(id)
	if err0 != ErrNone {
		return nil, err0
	}

	err1 := merkle.CheckProofTotal(proofTy, proof, id, val, dig)
	if err1 != ErrNone {
		return nil, err1
	}

	// If we don't have dig, add it. Otherwise, compare against what we have.
	origDig, ok := c.Digs[epoch]
	if ok {
		if !std.BytesEqual(origDig, dig) {
			return nil, ErrSome
		}
	} else {
		c.Digs[epoch] = dig
	}
	return val, ErrNone
}

/*
Note: potential attack.
Key serv refuses to fill in a hole, even though we have bigger digests.
*/

// Verified through Epoch idx in retval.
func (c *KeyCli) Audit(adtrId uint64) (Epoch, Error) {
	var link Link
	var epoch uint64
	var stop bool
	for !stop {
		var dig merkle.Digest
		dig, ok0 := c.Digs[epoch]
		if !ok0 {
			newDig, err0 := c.Serv.GetDigest(epoch)
			if err0 != ErrNone {
				stop = true
				continue
			}
			c.Digs[epoch] = newDig
			dig = newDig
		}
		link = CalcNextLink(link, dig)
		epoch++
	}
	if epoch == 0 {
		return 0, ErrSome
	}

	adtr := c.Adtrs[adtrId]
	adtrVk := c.AdtrVks[adtrId]
	adtrLink, sig, err1 := adtr.GetLink(epoch)
	if err1 != ErrNone {
		return 0, err1
	}

	encB := (&EpochHash{Epoch: epoch, Hash: link}).Encode()
	ok1 := shim.Verify(adtrVk, encB, sig)
	if !ok1 {
		return 0, ErrSome
	}
	if !std.BytesEqual(link, adtrLink) {
		return 0, ErrSome
	}

	return epoch, ErrNone
}

// TODO: this is a client's keycli. where's the api for getting their own key?

// Verified through Epoch idx in retval.
func (c *KeyCli) SelfAudit() (Epoch, Error) {
	id := c.Id
	numVals := uint64(len(c.Vals))
	var valIdx uint64
	var epoch Epoch
	var stop bool
	for !stop {
		// Might be at the next val.
		if valIdx != numVals {
			epochChange := c.ValEpochs[valIdx]
			if epoch == epochChange {
				valIdx++
			}
		}
		var expProofTy merkle.ProofTy
		var expVal merkle.Val
		// Might be before we even put a val.
		if valIdx != 0 {
			expProofTy = merkle.MembProofTy
			expVal = c.Vals[valIdx-1]
		}

		_, dig, proofTy, proof, err0 := c.Serv.GetIdAtEpoch(id, epoch)
		if err0 != ErrNone {
			stop = true
			continue
		}
		if proofTy != expProofTy {
			stop = true
			continue
		}
		err1 := merkle.CheckProofTotal(proofTy, proof, id, expVal, dig)
		if err1 != ErrNone {
			stop = true
			continue
		}
		// Might not have the dig stored already.
		origDig, ok0 := c.Digs[epoch]
		if !ok0 {
			c.Digs[epoch] = dig
		} else if !std.BytesEqual(dig, origDig) {
			stop = true
			continue
		}
		epoch++
	}

	if epoch == 0 {
		return 0, ErrSome
	}
	return epoch - 1, ErrNone
}

/*
// Tests.

// Two clients lookup the same uname, talk to some auditor servers
// (at least one honest), and assert that their returned keys are the same.
func testAuditPass(servAddr grove_ffi.Address, adtrAddrs []grove_ffi.Address) {
	// Start the server.
	go func() {
		s := NewKeyServ()
		s.start(servAddr)
	}()
	machine.Sleep(1_000_000)

	// Make auditor keys.
	badSk0, badVk0 := kt_shim.MakeKeys()
	goodSk0, goodVk0 := kt_shim.MakeKeys()
	badSk1, badVk1 := kt_shim.MakeKeys()
	var adtrVks []*kt_shim.VerifierT
	adtrVks = append(adtrVks, badVk0)
	adtrVks = append(adtrVks, goodVk0)
	adtrVks = append(adtrVks, badVk1)

	// Start the auditors.
	go func() {
		a := newAuditor(badSk0)
		a.start(adtrAddrs[0])
	}()
	go func() {
		a := newAuditor(goodSk0)
		a.start(adtrAddrs[1])
	}()
	go func() {
		a := newAuditor(badSk1)
		a.start(adtrAddrs[2])
	}()
	machine.Sleep(1_000_000)

	// Start the clients.
	cReg := newKeyCli(servAddr, adtrAddrs, adtrVks)
	cLook0 := newKeyCli(servAddr, adtrAddrs, adtrVks)
	cLook1 := newKeyCli(servAddr, adtrAddrs, adtrVks)

	// Register a key.
	uname0 := uint64(42)
	key0 := []byte("key0")
	goodEntry := &shared.UnameKey{Uname: uname0, Key: key0}
	_, err0 := cReg.register(goodEntry)
	machine.Assume(err0 == shared.ErrNone)

	// Lookup that uname.
	epoch0, retKey0, err1 := cLook0.lookup(uname0)
	machine.Assume(err1 == shared.ErrNone)
	epoch1, retKey1, err2 := cLook1.lookup(uname0)
	machine.Assume(err2 == shared.ErrNone)

	// Start the auditors.
	badAdtr0 := urpc.MakeClient(adtrAddrs[0])
	goodAdtr0 := urpc.MakeClient(adtrAddrs[1])
	badAdtr1 := urpc.MakeClient(adtrAddrs[2])

	// Update the bad auditors.
	uname1 := uint64(43)
	key1 := []byte("key1")
	badEntry := &shared.UnameKey{Uname: uname1, Key: key1}
	badLog := shared.NewKeyLog()
	badLog.Append(badEntry)
	badLogB := badLog.Encode()
	emptyB := make([]byte, 0)
	err3 := badAdtr0.Call(shared.RpcAdtr_Update, badLogB, &emptyB, 100)
	machine.Assume(err3 == urpc.ErrNone)
	err4 := badAdtr1.Call(shared.RpcAdtr_Update, badLogB, &emptyB, 100)
	machine.Assume(err4 == urpc.ErrNone)

	// Update the good auditor.
	goodLog := shared.NewKeyLog()
	goodLog.Append(goodEntry)
	goodLogB := goodLog.Encode()
	err5 := goodAdtr0.Call(shared.RpcAdtr_Update, goodLogB, &emptyB, 100)
	machine.Assume(err5 == urpc.ErrNone)

	// Contact auditors.
	// A dishonest auditor can give us anything, we don't trust it.
	// But we call it here to show we can handle its output without panic'ing.
	_, _ = cLook0.audit(0)
	auditEpoch0, err6 := cLook0.audit(1)
	// Could do a more fine-grained check like
	// "if the sig passed, assert no other err".
	machine.Assume(err6 == shared.ErrNone)

	_, _ = cLook1.audit(2)
	auditEpoch1, err7 := cLook1.audit(1)
	machine.Assume(err7 == shared.ErrNone)

	// Big assert.
	if epoch0 == epoch1 && epoch0 <= auditEpoch0 && epoch1 <= auditEpoch1 {
		machine.Assert(shared.BytesEqual(retKey0, retKey1))
	}
}
*/
