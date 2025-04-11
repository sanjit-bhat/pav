package kt

import (
	"sync"

	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/cryptoutil"
	"github.com/mit-pdos/pav/merkle"
)

type Server struct {
	mu    *sync.RWMutex
	sigSk *cryptoffi.SigPrivateKey
	vrfSk *cryptoffi.VrfPrivateKey
	// commitSecret is the 32-byte secret used to generate commitments.
	commitSecret []byte
	// keyMap stores (mapLabel, mapVal) entries.
	keyMap *merkle.Tree
	// userInfo stores info about every registered uid.
	userInfo map[uint64]*userState
	// epochHist stores info about prior epochs, for auditing.
	epochHist []*servEpochInfo
	// workQ batch processes Put requests.
	workQ *WorkQ
}

type userState struct {
	// numVers provides the authoritative number of registered versions,
	// which corresponds to keyMap entries.
	numVers uint64
	// plainPk stores the plaintext pk, whereas keyMap only has commitments.
	plainPk []byte
}

type servEpochInfo struct {
	// updates stores (mapLabel, mapVal) keyMap updates.
	updates map[string][]byte
	dig     []byte
	sig     []byte
}

// Put errors iff there's a put of the same uid at the same time.
func (s *Server) Put(uid uint64, pk []byte) (*SigDig, *Memb, *NonMemb, bool) {
	work := &Work{Req: &WQReq{Uid: uid, Pk: pk}}
	s.workQ.Do(work)
	resp := work.Resp
	return resp.Dig, resp.Lat, resp.Bound, resp.Err
}

// Get returns a complete history proof for uid.
// if uid is not yet registered, it returns an empty memb proof for
// for the latest version.
func (s *Server) Get(uid uint64) (*SigDig, []*MembHide, bool, *Memb, *NonMemb) {
	s.mu.RLock()
	user := s.userInfo[uid]
	var numVers uint64
	var plainPk []byte
	if user != nil {
		numVers = user.numVers
		plainPk = user.plainPk
	}

	dig := getDig(s.epochHist)
	hist := getHist(s.keyMap, uid, numVers, s.vrfSk)
	isReg, latest := getLatest(s.keyMap, uid, numVers, s.vrfSk, s.commitSecret, plainPk)
	bound := getBound(s.keyMap, uid, numVers, s.vrfSk)
	s.mu.RUnlock()
	return dig, hist, isReg, latest, bound
}

func (s *Server) SelfMon(uid uint64) (*SigDig, *NonMemb) {
	s.mu.RLock()
	user := s.userInfo[uid]
	var numVers uint64
	if user != nil {
		numVers = user.numVers
	}

	dig := getDig(s.epochHist)
	bound := getBound(s.keyMap, uid, numVers, s.vrfSk)
	s.mu.RUnlock()
	return dig, bound
}

// Audit returns an err on fail.
func (s *Server) Audit(epoch uint64) (*UpdateProof, bool) {
	s.mu.RLock()
	if epoch >= uint64(len(s.epochHist)) {
		s.mu.RUnlock()
		return &UpdateProof{Updates: make(map[string][]byte)}, true
	}
	info := s.epochHist[epoch]
	s.mu.RUnlock()
	return &UpdateProof{Updates: info.updates, Sig: info.sig}, false
}

type WQReq struct {
	Uid uint64
	Pk  []byte
}

type WQResp struct {
	Dig   *SigDig
	Lat   *Memb
	Bound *NonMemb
	Err   bool
}

type mapper0Out struct {
	latestVrfHash  []byte
	latestVrfProof []byte
	boundVrfHash   []byte
	boundVrfProof  []byte
	mapVal         []byte
	pkOpen         *CommitOpen
}

func (s *Server) Worker() {
	work := s.workQ.Get()

	// error out duplicates.
	uidSet := make(map[uint64]bool, len(work))
	for _, w := range work {
		w.Resp = &WQResp{}
		uid := w.Req.Uid
		_, ok := uidSet[uid]
		if ok {
			w.Resp.Err = true
			w.Resp.Lat = &Memb{PkOpen: &CommitOpen{}}
			w.Resp.Bound = &NonMemb{}
		} else {
			uidSet[uid] = false
		}
	}

	// NOTE: there are no other write lockers outside this fn.
	// as a result, in this fn, the 3 critical sections view:
	//
	//  1. current server.
	//  2. current server to new server.
	//  3. new server.
	//
	// this is essential to make proper proofs and maintain the server invariant.

	// map 0.
	outs0 := make([]*mapper0Out, len(work))
	var wg = new(sync.WaitGroup)
	var i uint64
	for ; i < uint64(len(work)); i++ {
		resp := work[i].Resp
		if !resp.Err {
			req := work[i].Req
			out0 := &mapper0Out{}
			outs0[i] = out0
			wg.Add(1)
			go func() {
				s.mapper0(req, out0)
				wg.Done()
			}()
		}
	}
	wg.Wait()

	// update server with new entries.
	s.mu.Lock()
	upd := make(map[string][]byte, len(work))
	i = 0
	for ; i < uint64(len(work)); i++ {
		resp := work[i].Resp
		if !resp.Err {
			req := work[i].Req
			out0 := outs0[i]
			label := out0.latestVrfHash

			err0 := s.keyMap.Put(label, out0.mapVal)
			std.Assert(!err0)
			upd[string(label)] = out0.mapVal
			var user = s.userInfo[req.Uid]
			if user == nil {
				user = &userState{}
			}
			user.numVers += 1
			user.plainPk = req.Pk
			s.userInfo[req.Uid] = user
		}
	}
	updEpochHist(&s.epochHist, upd, s.keyMap.Digest(), s.sigSk)
	s.mu.Unlock()

	// map 1.
	wg = new(sync.WaitGroup)
	i = 0
	for ; i < uint64(len(work)); i++ {
		resp := work[i].Resp
		if !resp.Err {
			out0 := outs0[i]
			wg.Add(1)
			go func() {
				s.mapper1(out0, resp)
				wg.Done()
			}()
		}
	}
	wg.Wait()

	s.workQ.Finish(work)
}

// mapper0 makes mapLabels and mapVals.
func (s *Server) mapper0(in *WQReq, out *mapper0Out) {
	user := s.userInfo[in.Uid]
	var numVers uint64
	if user != nil {
		numVers = user.numVers
	}
	latHash, latProof := compMapLabel(in.Uid, numVers, s.vrfSk)
	boundHash, boundProof := compMapLabel(in.Uid, numVers+1, s.vrfSk)

	nextEpoch := uint64(len(s.epochHist))
	r := compCommitOpen(s.commitSecret, latHash)
	open := &CommitOpen{Val: in.Pk, Rand: r}
	mapVal := compMapVal(nextEpoch, open)

	out.latestVrfHash = latHash
	out.latestVrfProof = latProof
	out.boundVrfHash = boundHash
	out.boundVrfProof = boundProof
	out.mapVal = mapVal
	out.pkOpen = open
}

// mapper1 computes merkle proofs and assembles full response.
func (s *Server) mapper1(in *mapper0Out, out *WQResp) {
	latIn, _, latMerk := s.keyMap.Prove(in.latestVrfHash)
	std.Assert(latIn)

	boundIn, _, boundMerk := s.keyMap.Prove(in.boundVrfHash)
	std.Assert(!boundIn)

	out.Dig = getDig(s.epochHist)
	out.Lat = &Memb{
		LabelProof:  in.latestVrfProof,
		EpochAdded:  uint64(len(s.epochHist)) - 1,
		PkOpen:      in.pkOpen,
		MerkleProof: latMerk,
	}
	out.Bound = &NonMemb{
		LabelProof:  in.boundVrfProof,
		MerkleProof: boundMerk,
	}
}

func NewServer() (*Server, cryptoffi.SigPublicKey, *cryptoffi.VrfPublicKey) {
	mu := new(sync.RWMutex)
	sigPk, sigSk := cryptoffi.SigGenerateKey()
	vrfPk, vrfSk := cryptoffi.VrfGenerateKey()
	sec := cryptoffi.RandBytes(cryptoffi.HashLen)
	keys := merkle.NewTree()
	users := make(map[uint64]*userState)
	var hist []*servEpochInfo
	// commit empty tree as init epoch.
	updEpochHist(&hist, make(map[string][]byte), keys.Digest(), sigSk)
	wq := NewWorkQ()
	s := &Server{mu: mu, sigSk: sigSk, vrfSk: vrfSk, commitSecret: sec, keyMap: keys, userInfo: users, epochHist: hist, workQ: wq}

	go func() {
		for {
			s.Worker()
		}
	}()
	return s, sigPk, vrfPk
}

// compMapLabel rets the vrf output and proof for mapLabel (VRF(uid || ver)).
func compMapLabel(uid uint64, ver uint64, sk *cryptoffi.VrfPrivateKey) ([]byte, []byte) {
	l := &MapLabelPre{Uid: uid, Ver: ver}
	lByt := MapLabelPreEncode(make([]byte, 0, 16), l)
	return sk.Prove(lByt)
}

// compMapVal rets mapVal (epoch || Hash(pk || rand)).
func compMapVal(epoch uint64, pkOpen *CommitOpen) []byte {
	openByt := CommitOpenEncode(make([]byte, 0, 8+uint64(len(pkOpen.Val))+8+cryptoffi.HashLen), pkOpen)
	commit := cryptoutil.Hash(openByt)
	v := &MapValPre{Epoch: epoch, PkCommit: commit}
	return MapValPreEncode(make([]byte, 0, 8+8+cryptoffi.HashLen), v)
}

func compCommitOpen(secret, label []byte) []byte {
	var b = make([]byte, 0, 2*cryptoffi.HashLen)
	b = append(b, secret...)
	b = append(b, label...)
	return cryptoutil.Hash(b)
}

// updEpochHist does a signed history update with some new entries.
func updEpochHist(hist *[]*servEpochInfo, upd map[string][]byte, dig []byte, sk *cryptoffi.SigPrivateKey) {
	epoch := uint64(len(*hist))
	preSig := &PreSigDig{Epoch: epoch, Dig: dig}
	preSigByt := PreSigDigEncode(make([]byte, 0, 8+8+cryptoffi.HashLen), preSig)
	sig := sk.Sign(preSigByt)
	// benchmark: turn off sigs for akd compat.
	// _ = sk
	// var sig []byte
	newInfo := &servEpochInfo{updates: upd, dig: dig, sig: sig}
	*hist = append(*hist, newInfo)
}

func getDig(hist []*servEpochInfo) *SigDig {
	numEpochs := uint64(len(hist))
	lastInfo := hist[numEpochs-1]
	return &SigDig{Epoch: numEpochs - 1, Dig: lastInfo.dig, Sig: lastInfo.sig}
}

// getHist returns membership proofs for the history of versions
// up until the latest.
func getHist(keyMap *merkle.Tree, uid, numVers uint64, vrfSk *cryptoffi.VrfPrivateKey) []*MembHide {
	if numVers == 0 {
		return nil
	}
	// latest registered ver not included in hist.
	var hist = make([]*MembHide, 0, numVers-1)
	// for ver := uint64(0); ver < numVers-1; ver++ {
	var ver = uint64(0)
	for ver < numVers-1 {
		label, labelProof := compMapLabel(uid, ver, vrfSk)
		inMap, mapVal, mapProof := keyMap.Prove(label)
		std.Assert(inMap)
		hist = append(hist, &MembHide{LabelProof: labelProof, MapVal: mapVal, MerkleProof: mapProof})
		ver++
	}
	return hist
}

// getLatest returns whether a version is registered, and if so,
// a membership proof for the latest version.
func getLatest(keyMap *merkle.Tree, uid, numVers uint64, vrfSk *cryptoffi.VrfPrivateKey, commitSecret, pk []byte) (bool, *Memb) {
	if numVers == 0 {
		return false, &Memb{PkOpen: &CommitOpen{}}
	}
	label, labelProof := compMapLabel(uid, numVers-1, vrfSk)
	inMap, mapVal, mapProof := keyMap.Prove(label)
	std.Assert(inMap)
	valPre, _, err1 := MapValPreDecode(mapVal)
	std.Assert(!err1)
	r := compCommitOpen(commitSecret, label)
	open := &CommitOpen{Val: pk, Rand: r}
	return true, &Memb{LabelProof: labelProof, EpochAdded: valPre.Epoch, PkOpen: open, MerkleProof: mapProof}
}

// getBound returns a non-membership proof for the boundary version.
func getBound(keyMap *merkle.Tree, uid, numVers uint64, vrfSk *cryptoffi.VrfPrivateKey) *NonMemb {
	label, labelProof := compMapLabel(uid, numVers, vrfSk)
	inMap, _, mapProof := keyMap.Prove(label)
	std.Assert(!inMap)
	return &NonMemb{LabelProof: labelProof, MerkleProof: mapProof}
}
