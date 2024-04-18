package ktMerkle

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/secure-chat/crypto/helpers"
	"github.com/mit-pdos/secure-chat/crypto/shim"
	"github.com/mit-pdos/secure-chat/merkle"
	//"github.com/tchajed/goose/machine"
	"sync"
)

// Key server.

type Link = []byte

type KeyServ struct {
	Mu     *sync.Mutex
	Trees  []*merkle.Tree
	NextTr *merkle.Tree
	Chain  []Link
}

func NewKeyServ() *KeyServ {
	s := &KeyServ{}
	s.Mu = new(sync.Mutex)
	return s
}

func (s *KeyServ) UpdateEpoch() {
	s.Mu.Lock()
	var hr helpers.Hasher
	if uint64(len(s.Chain)) > 0 {
		lastLink := s.Chain[uint64(len(s.Chain))-1]
		helpers.HasherWrite(&hr, lastLink)
	}
	helpers.HasherWrite(&hr, s.NextTr.Digest())
	newLink := helpers.HasherSum(hr, nil)

	s.Chain = append(s.Chain, newLink)
	s.Trees = append(s.Trees, s.NextTr)
	s.NextTr = s.NextTr.DeepCopy()
	s.Mu.Unlock()
}

// toEpoch exclusive.
func (s *KeyServ) GetDigestsRange(fromEpoch, toEpoch uint64) []merkle.Digest {
	var digs []merkle.Digest
	var i uint64 = fromEpoch
	for ; i < uint64(len(s.Trees)) && i < toEpoch; i++ {
		tr := s.Trees[i]
		digs = append(digs, tr.Digest())
	}
	return digs
}

func (s *KeyServ) GetDigestsFrom(fromEpoch uint64) []merkle.Digest {
	return s.GetDigestsRange(fromEpoch, uint64(len(s.Trees)))
}

func (s *KeyServ) GetDigests(fromEpoch uint64) []merkle.Digest {
	s.Mu.Lock()
	digs := s.GetDigestsFrom(fromEpoch)
	s.Mu.Unlock()
	return digs
}

func (s *KeyServ) GetProofs(id merkle.Id, fromEpoch, toEpoch uint64) ([]merkle.ProofT, []merkle.GenProof, ErrorT) {
	var proofTs []merkle.ProofT
	var proofs []merkle.GenProof
	var err merkle.ErrorT
	var i uint64 = fromEpoch
	for ; i < toEpoch && i < uint64(len(s.Trees)); i++ {
		tr := s.Trees[i]
		proofT, _, _, proof, err2 := tr.GetTotal(id)
		if err2 != merkle.ErrNone {
			err = err2
			continue
		}
		proofTs = append(proofTs, proofT)
		proofs = append(proofs, proof)
	}
	return proofTs, proofs, err
}

func (s *KeyServ) Put(id merkle.Id, val merkle.Val, fromEpoch uint64) ([]merkle.Digest, []merkle.GenProof, ErrorT) {
	s.Mu.Lock()
	digs := s.GetDigestsFrom(fromEpoch)
	_, proofs, err0 := s.GetProofs(id, fromEpoch, uint64(len(s.Trees)))
	if err0 != ErrNone {
		s.Mu.Unlock()
		return nil, nil, err0
	}
	_, _, err1 := s.NextTr.Put(id, val)
	s.Mu.Unlock()
	return digs, proofs, err1
}

func (s *KeyServ) GetId(id merkle.Id, fromEpoch uint64) ([]merkle.Digest, merkle.ProofT, merkle.Val, merkle.GenProof, ErrorT) {
	s.Mu.Lock()
	digs := s.GetDigestsFrom(fromEpoch)
	tr := s.Trees[uint64(len(s.Trees))-1]
	proofT, val, _, proof, err := tr.GetTotal(id)
	s.Mu.Unlock()
	return digs, proofT, val, proof, err
}

// toEpoch exists because I imagine this being a more retrospective op.
func (s *KeyServ) GetIdHist(id merkle.Id, fromEpoch, toEpoch uint64) ([]merkle.Digest, []merkle.GenProof, ErrorT) {
	s.Mu.Lock()
	digs := s.GetDigestsRange(fromEpoch, toEpoch)
	_, proofs, err := s.GetProofs(id, fromEpoch, toEpoch)
	s.Mu.Unlock()
	return digs, proofs, err
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

// fromEpoch is when the digs start.
func (a *Auditor) Update(fromEpoch uint64, digs []merkle.Digest) ErrorT {
	a.Mu.Lock()
	chainLen := uint64(len(a.Chain))
	digsLen := uint64(len(digs))
	// Are the digests in range of our chain and enough to extend it?
	if fromEpoch > chainLen {
		a.Mu.Unlock()
		return ErrSome
	}
	if fromEpoch+digsLen <= chainLen {
		a.Mu.Unlock()
		return ErrSome
	}
	digsNew := digs[chainLen-fromEpoch:]

	for _, dig := range digsNew {
		chainLenNew := uint64(len(a.Chain))
		var hr helpers.Hasher
		if chainLenNew > 0 {
			lastLink := a.Chain[chainLenNew-1]
			helpers.HasherWrite(&hr, lastLink)
		}
		helpers.HasherWrite(&hr, dig)
		newLink := helpers.HasherSum(hr, nil)
		a.Chain = append(a.Chain, newLink)
	}
	a.Mu.Unlock()
	return ErrNone
}

func (a *Auditor) GetLink(epoch uint64) (Link, ErrorT) {
	a.Mu.Lock()
	if epoch >= uint64(len(a.Chain)) {
		a.Mu.Unlock()
		return nil, ErrSome
	}
	link := a.Chain[epoch]
	a.Mu.Unlock()
	return link, ErrNone
}

// Key client.

type KeyCli struct {
	Adtrs         []*Auditor
	AdtrVks       []shim.VerifierT
	Digs          []merkle.Digest
	Id            merkle.Id
	LastLink      Link
	CurrVal       merkle.Val
	CurrValSet    bool
	NextSelfAudit uint64
	Serv          *KeyServ
}

func NewKeyCli(id merkle.Id, serv *KeyServ, adtrs []*Auditor, adtrVks []shim.VerifierT) *KeyCli {
	return &KeyCli{Adtrs: adtrs, AdtrVks: adtrVks, Digs: nil, Id: id,
		LastLink: nil, CurrVal: nil, CurrValSet: false,
		NextSelfAudit: 0, Serv: serv}
}

func batchCheckProofs(proofT merkle.ProofT, id merkle.Id, val merkle.Val, digs []merkle.Digest, proofs []merkle.GenProof) ErrorT {
	digsLen := uint64(len(digs))
	proofsLen := uint64(len(proofs))
	if digsLen != proofsLen {
		return ErrSome
	}

	var err0 ErrorT
	var i uint64
	for ; i < digsLen; i++ {
		dig := digs[i]
		proof := proofs[i]
		err1 := merkle.CheckProofTotal(proofT, proof, id, val, dig)
		if err1 != ErrNone {
			err0 = err1
		}
	}
	return err0
}

func (c *KeyCli) Put(val merkle.Val) ErrorT {
	nextSelfAudit := c.NextSelfAudit
	digs, proofs, err0 := c.Serv.Put(c.Id, val, nextSelfAudit)
	if err0 != ErrNone {
		return err0
	}

	// Check proofs.
	var proofT merkle.ProofT = merkle.NonmembProofT
	if c.CurrValSet {
		proofT = merkle.MembProofT
	}
	err1 := batchCheckProofs(proofT, c.Id, c.CurrVal, digs, proofs)
	if err1 != ErrNone {
		return err1
	}

	// Check old digs match up with prior and update new digs.
	nextEpoch := uint64(len(c.Digs))
	cutoff := nextEpoch - nextSelfAudit
	oldDigs := digs[:cutoff]
	newDigs := digs[cutoff:]

	var err2 ErrorT
	for loopIdx, servDig := range oldDigs {
		digIdx := uint64(loopIdx) + nextSelfAudit
		ourDig := c.Digs[digIdx]
		if !std.BytesEqual(servDig, ourDig) {
			err2 = ErrSome
		}
	}
	if err2 != ErrNone {
		return err2
	}

	var newLink Link = c.LastLink
	for _, dig := range newDigs {
		c.Digs = append(c.Digs, dig)
		var hr helpers.Hasher
		helpers.HasherWrite(&hr, newLink)
		helpers.HasherWrite(&hr, dig)
		newLink = helpers.HasherSum(hr, nil)
	}

	// Update curr vals.
	c.CurrVal = val
	c.CurrValSet = true
	c.NextSelfAudit = uint64(len(c.Digs))

	return ErrNone
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
