package kt

import (
	"github.com/goose-lang/goose/machine"
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
	errNone   errorTy = false
	errSome   errorTy = true
	maxUint64 uint64  = 1<<64 - 1
)

type epochChain struct {
	epochs []*epochInfo
}

type epochInfo struct {
	keyMap   *merkle.Tree
	prevLink linkTy
	dig      merkle.Digest
	link     linkTy
	linkSig  cryptoffi.Sig
}

func (c *epochChain) put(tree *merkle.Tree, sk cryptoffi.PrivateKey) {
	chainLen := uint64(len(c.epochs))
	var prevLink linkTy
	if chainLen > 0 {
		lastEpoch := c.epochs[chainLen-1]
		prevLink = lastEpoch.link
	} else {
		prePrevLink := (&chainSepNone{}).encode()
		prevLink = cryptoffi.Hash(prePrevLink)
	}

	dig := tree.Digest()
	preLink := (&chainSepSome{epoch: chainLen, prevLink: prevLink, data: dig}).encode()
	link := cryptoffi.Hash(preLink)
	sepLink := (&servSepLink{link: link}).encode()
	sig := sk.Sign(sepLink)

	epoch := &epochInfo{keyMap: tree, prevLink: prevLink, dig: dig, link: link, linkSig: sig}
	c.epochs = append(c.epochs, epoch)
}

// KT server.

type server struct {
	sk    cryptoffi.PrivateKey
	mu    *sync.Mutex
	chain *epochChain
	// updates just for the current epoch.
	updates map[string][]byte
}

func newServer() (*server, cryptoffi.PublicKey) {
	pk, sk := cryptoffi.GenerateKey()
	mu := new(sync.Mutex)
	updates := make(map[string][]byte)

	// Make epoch 0 the empty map so we can serve early get reqs.
	emptyMap := &merkle.Tree{}
	chain := &epochChain{}
	chain.put(emptyMap, sk)
	return &server{sk: sk, mu: mu, chain: chain, updates: updates}, pk
}

// applyUpdates returns a new map with the updates applied to the current map.
func applyUpdates(currMap *merkle.Tree, updates map[string][]byte) *merkle.Tree {
	nextMap := currMap.DeepCopy()
	for id, val := range updates {
		idB := []byte(id)
		_, _, err := nextMap.Put(idB, val)
		// Put checks that all IDs have valid len, so there shouldn't be any errors.
		machine.Assert(!err)
	}
	return nextMap
}

func (s *server) updateEpoch() {
	s.mu.Lock()
	currMap := s.chain.epochs[uint64(len(s.chain.epochs))-1].keyMap
	nextMap := applyUpdates(currMap, s.updates)
	s.chain.put(nextMap, s.sk)
	s.updates = make(map[string][]byte)
	s.mu.Unlock()
}

// put schedules a put to be committed at the next epoch update.
func (s *server) put(id merkle.Id, val merkle.Val) *servPutReply {
	s.mu.Lock()
	errReply := &servPutReply{}
	errReply.error = errSome

	// After establishing this invariant, guaranteed that merkle tree
	// put will go thru.
	if uint64(len(id)) != cryptoffi.HashLen {
		s.mu.Unlock()
		return errReply
	}

	// Changing the same key twice per epoch might violate put promise.
	idS := string(id)
	_, ok := s.updates[idS]
	if ok {
		s.mu.Unlock()
		return errReply
	}
	s.updates[idS] = val

	// Put promise declares that we'll apply this change at the next epoch update.
	currEpoch := uint64(len(s.chain.epochs)) - 1
	sepPut := (&servSepPut{epoch: currEpoch + 1, id: id, val: val}).encode()
	putSig := s.sk.Sign(sepPut)

	// Pin the server down a little more by giving the current chain.
	info := s.chain.epochs[currEpoch]
	prevLink := info.prevLink
	dig := info.dig
	linkSig := info.linkSig
	s.mu.Unlock()
	return &servPutReply{putEpoch: currEpoch + 1, prevLink: prevLink, dig: dig, linkSig: linkSig, putSig: putSig, error: errNone}
}

func (s *server) getIdAt(id merkle.Id, epoch epochTy) *servGetIdAtReply {
	s.mu.Lock()
	errReply := &servGetIdAtReply{}
	errReply.error = errSome
	if epoch >= uint64(len(s.chain.epochs)) {
		s.mu.Unlock()
		return errReply
	}
	info := s.chain.epochs[epoch]
	reply := info.keyMap.Get(id)
	s.mu.Unlock()
	return &servGetIdAtReply{prevLink: info.prevLink, dig: info.dig, sig: info.linkSig, val: reply.Val, proofTy: reply.ProofTy, proof: reply.Proof, error: reply.Error}
}

func (s *server) getLink(epoch epochTy) *servGetLinkReply {
	s.mu.Lock()
	if epoch >= uint64(len(s.chain.epochs)) {
		errReply := &servGetLinkReply{}
		errReply.error = errSome
		s.mu.Unlock()
		return errReply
	}
	info := s.chain.epochs[epoch]
	s.mu.Unlock()
	return &servGetLinkReply{prevLink: info.prevLink, dig: info.dig, sig: info.linkSig, error: errNone}
}

// KT auditor.

// auditor is an append-only log of server signed links.
// e.g., the S3 auditor in WhatsApp's deployment.
type auditor struct {
	mu     *sync.Mutex
	sk     cryptoffi.PrivateKey
	servPk cryptoffi.PublicKey
	log    []*adtrLinkSigs
}

type adtrLinkSigs struct {
	prevLink linkTy
	dig      merkle.Digest
	link     linkTy
	servSig  cryptoffi.Sig
	adtrSig  cryptoffi.Sig
}

func newAuditor(servPk cryptoffi.PublicKey) (*auditor, cryptoffi.PublicKey) {
	pk, sk := cryptoffi.GenerateKey()
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
		preLink := (&chainSepNone{}).encode()
		cachedPrevLink = cryptoffi.Hash(preLink)
	} else {
		cachedPrevLink = a.log[epoch-1].link
	}
	if !std.BytesEqual(prevLink, cachedPrevLink) {
		a.mu.Unlock()
		return errSome
	}

	preLink := (&chainSepSome{epoch: epoch, prevLink: prevLink, data: dig}).encode()
	link := cryptoffi.Hash(preLink)
	sepLink := (&servSepLink{link: link}).encode()
	servOk := a.servPk.Verify(sepLink, servSig)
	if !servOk {
		a.mu.Unlock()
		return errSome
	}

	adtrSig := a.sk.Sign(sepLink)
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

type client struct {
	id     merkle.Id
	myVals timeSeries
	links  map[epochTy]*cliSigLink
	serv   *urpc.Client
	servPk cryptoffi.PublicKey
}

type cliSigLink struct {
	prevLink linkTy
	dig      merkle.Digest
	sig      cryptoffi.Sig
	link     linkTy
}

func newClient(id merkle.Id, servAddr grove_ffi.Address, servPk cryptoffi.PublicKey) *client {
	serv := urpc.MakeClient(servAddr)
	digs := make(map[epochTy]*cliSigLink)
	return &client{id: id, myVals: nil, links: digs, serv: serv, servPk: servPk}
}

func (c *client) addLink(epoch epochTy, prevLink linkTy, dig merkle.Digest, sig cryptoffi.Sig) (*evidServLink, errorTy) {
	preLink := (&chainSepSome{epoch: epoch, prevLink: prevLink, data: dig}).encode()
	link := cryptoffi.Hash(preLink)
	// Check that link sig verifies.
	sepLink := (&servSepLink{link: link}).encode()
	ok0 := c.servPk.Verify(sepLink, sig)
	if !ok0 {
		return nil, errSome
	}
	newSigLn := &signedLink{epoch: epoch, prevLink: prevLink, dig: dig, sig: sig}

	// Check if epoch already exists.
	cachedLink, ok1 := c.links[epoch]
	if ok1 && !std.BytesEqual(cachedLink.link, link) {
		cachedSigLn := &signedLink{epoch: epoch, prevLink: cachedLink.prevLink, dig: cachedLink.dig, sig: cachedLink.sig}
		evid := &evidServLink{sigLn0: newSigLn, sigLn1: cachedSigLn}
		return evid, errSome
	}

	// Check if epoch-1 already exists.
	cachedPrevLink, ok2 := c.links[epoch-1]
	if epoch > 0 && ok2 && !std.BytesEqual(cachedPrevLink.link, prevLink) {
		cachedSigLn := &signedLink{epoch: epoch - 1, prevLink: cachedLink.prevLink, dig: cachedLink.dig, sig: cachedLink.sig}
		evid := &evidServLink{sigLn0: cachedSigLn, sigLn1: newSigLn}
		return evid, errSome
	}

	// Check if epoch+1 already exists.
	cachedNextLink, ok3 := c.links[epoch+1]
	if epoch < maxUint64 && ok3 && !std.BytesEqual(link, cachedNextLink.prevLink) {
		cachedSigLn := &signedLink{epoch: epoch + 1, prevLink: cachedLink.prevLink, dig: cachedLink.dig, sig: cachedLink.sig}
		evid := &evidServLink{sigLn0: newSigLn, sigLn1: cachedSigLn}
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

	evid, err0 := c.addLink(reply.putEpoch-1, reply.prevLink, reply.dig, reply.linkSig)
	if err0 {
		return 0, evid, err0
	}

	sepPut := (&servSepPut{epoch: reply.putEpoch, id: c.id, val: val}).encode()
	ok := c.servPk.Verify(sepPut, reply.putSig)
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
// TODO: maybe split cross-epoch consistency check into sep routine.
// it seems nice to have (but not necessary) for both audit and selfCheck.
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
	adtrOk := adtrPk.Verify(preAdtrSig, reply.adtrSig)
	if !adtrOk {
		return 0, nil, errSome
	}

	// Check serv sig.
	preServSig := (&servSepLink{link: adtrLink}).encode()
	servOk := c.servPk.Verify(preServSig, reply.servSig)
	if !servOk {
		return 0, nil, errSome
	}

	// Check if our chain diverges from adtr.
	if !std.BytesEqual(lastLink.link, adtrLink) {
		adtrSigLn := &signedLink{epoch: lastEpoch, prevLink: reply.prevLink, dig: reply.dig, sig: reply.servSig}
		mySigLn := &signedLink{epoch: lastEpoch, prevLink: lastLink.prevLink, dig: lastLink.dig, sig: lastLink.sig}
		evid := &evidServLink{sigLn0: adtrSigLn, sigLn1: mySigLn}
		return 0, evid, errSome
	}
	return epoch, nil, errNone
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
			sigLn := &signedLink{epoch: epoch, prevLink: reply.prevLink, dig: reply.dig, sig: reply.sig}
			sigPut := &signedPut{epoch: epoch, id: c.id, val: expVal, sig: putSig}
			evid := &evidServPut{sigLn: sigLn, sigPut: sigPut, val: reply.val, proof: reply.proof}
			return nil, evid, errSome
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

// timeSeries converts a series of value updates into a view of the latest value
// at any given time.
// TODO: this is a bad abstraction. Too complicated of an API for what it provides.
// Fix when I get to proving the selfCheck function.
type timeSeries []timeEntry

type timeEntry struct {
	time epochTy
	val  merkle.Val
	// Type servSigSepPut.
	sig cryptoffi.Sig
}

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
		if te.time <= epoch {
			latest = te.val
			init = true
			sig = te.sig
			boundary = te.time == epoch
		}
	}
	return latest, init, sig, boundary
}
