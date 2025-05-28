package server

import (
	"sync"

	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/cryptoutil"
	"github.com/mit-pdos/pav/ktserde"
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
	// WorkQ batch processes Put requests.
	WorkQ *WorkQ
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
func (s *Server) Put(uid uint64, pk []byte, ver uint64) bool {
	resp := s.WorkQ.Do(&WQReq{Uid: uid, Pk: pk, Ver: ver})
	return resp.Err
}

// Get returns a complete history proof for uid.
// if uid is not yet registered, it returns an empty memb proof for
// for the latest version.
func (s *Server) Get(uid uint64) (*ktserde.SigDig, []*ktserde.MembHide, bool, *ktserde.Memb, *ktserde.NonMemb) {
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

func (s *Server) SelfMon(uid uint64) (*ktserde.SigDig, *ktserde.NonMemb) {
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
func (s *Server) Audit(epoch uint64) (*ktserde.UpdateProof, bool) {
	s.mu.RLock()
	if epoch >= uint64(len(s.epochHist)) {
		s.mu.RUnlock()
		return &ktserde.UpdateProof{Updates: make(map[string][]byte)}, true
	}
	info := s.epochHist[epoch]
	s.mu.RUnlock()
	return &ktserde.UpdateProof{Updates: info.updates, Sig: info.sig}, false
}

type WQReq struct {
	Uid uint64
	Pk  []byte
	Ver uint64
}

type WQResp struct {
	Err bool
}

type mapperOut struct {
	mapLabel []byte
	mapVal   []byte
}

func (s *Server) Worker() {
	work := s.WorkQ.Get()

	uidSet := make(map[uint64]bool, len(work))
	for _, w := range work {
		w.Resp = &WQResp{}
		uid := w.Req.Uid
		ver := w.Req.Ver

		// error out wrong versions.
		user, ok0 := s.userInfo[uid]
		if ok0 && ver != user.numVers {
			w.Resp.Err = true
			continue
		}

		// error out duplicate uid's. arbitrarily picks one to succeed.
		_, ok1 := uidSet[uid]
		if ok1 {
			w.Resp.Err = true
		} else {
			uidSet[uid] = false
		}
	}

	// NOTE: it's important that there are no write lockers outside this fn.
	// this allows critical section #2 (write) to start with the
	// same state as critical section #1 (read).

	// in parallel, map requests to keyMap updates.
	outs := make([]*mapperOut, len(work))
	var i uint64
	for i < uint64(len(work)) {
		outs[i] = &mapperOut{}
		i++
	}
	wg := new(sync.WaitGroup)
	i = 0
	for i < uint64(len(work)) {
		resp := work[i].Resp
		if !resp.Err {
			req := work[i].Req
			out := outs[i]
			wg.Add(1)
			go func() {
				s.mapper(req, out)
				wg.Done()
			}()
		}
		i++
	}
	wg.Wait()

	// apply updates to server.
	s.mu.Lock()
	upd := make(map[string][]byte, len(work))
	i = 0
	for i < uint64(len(work)) {
		resp := work[i].Resp
		if !resp.Err {
			req := work[i].Req
			out0 := outs[i]
			label := out0.mapLabel

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
		i++
	}
	s.updEpochHist(upd)
	s.mu.Unlock()

	// signal that we finished work.
	for _, w := range work {
		w.Finish()
	}
}

// mapper makes mapLabels and mapVals.
func (s *Server) mapper(in *WQReq, out *mapperOut) {
	user := s.userInfo[in.Uid]
	var numVers uint64
	if user != nil {
		numVers = user.numVers
	}
	mapLabel, _ := CompMapLabel(in.Uid, numVers, s.vrfSk)

	nextEpoch := uint64(len(s.epochHist))
	r := compCommitOpen(s.commitSecret, mapLabel)
	open := &ktserde.CommitOpen{Val: in.Pk, Rand: r}
	mapVal := CompMapVal(nextEpoch, open)

	out.mapLabel = mapLabel
	out.mapVal = mapVal
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
	wq := NewWorkQ()
	s := &Server{mu: mu, sigSk: sigSk, vrfSk: vrfSk, commitSecret: sec, keyMap: keys, userInfo: users, epochHist: hist, WorkQ: wq}
	s.updEpochHist(make(map[string][]byte))

	go func() {
		for {
			s.Worker()
		}
	}()
	return s, sigPk, vrfPk
}

// CompMapLabel rets the vrf output and proof for mapLabel (VRF(uid || ver)).
func CompMapLabel(uid uint64, ver uint64, sk *cryptoffi.VrfPrivateKey) ([]byte, []byte) {
	l := &ktserde.MapLabelPre{Uid: uid, Ver: ver}
	lByt := ktserde.MapLabelPreEncode(make([]byte, 0, 16), l)
	return sk.Prove(lByt)
}

// CompMapVal rets mapVal (epoch || Hash(pk || rand)).
func CompMapVal(epoch uint64, pkOpen *ktserde.CommitOpen) []byte {
	openByt := ktserde.CommitOpenEncode(make([]byte, 0, 8+uint64(len(pkOpen.Val))+8+cryptoffi.HashLen), pkOpen)
	commit := cryptoutil.Hash(openByt)
	v := &ktserde.MapValPre{Epoch: epoch, PkCommit: commit}
	return ktserde.MapValPreEncode(make([]byte, 0, 8+8+cryptoffi.HashLen), v)
}

func compCommitOpen(secret, label []byte) []byte {
	var b = make([]byte, 0, 2*cryptoffi.HashLen)
	b = append(b, secret...)
	b = append(b, label...)
	return cryptoutil.Hash(b)
}

// updEpochHist does a signed history update with some new entries.
func (s *Server) updEpochHist(upd map[string][]byte) {
	sk := s.sigSk
	dig := s.keyMap.Digest()
	epoch := uint64(len(s.epochHist))
	preSig := &ktserde.PreSigDig{Epoch: epoch, Dig: dig}
	preSigByt := ktserde.PreSigDigEncode(make([]byte, 0, 8+8+cryptoffi.HashLen), preSig)
	sig := sk.Sign(preSigByt)
	// benchmark: turn off sigs for akd compat.
	// _ = sk
	// var sig []byte
	newInfo := &servEpochInfo{updates: upd, dig: dig, sig: sig}
	s.epochHist = append(s.epochHist, newInfo)
}

func getDig(hist []*servEpochInfo) *ktserde.SigDig {
	numEpochs := uint64(len(hist))
	lastInfo := hist[numEpochs-1]
	return &ktserde.SigDig{Epoch: numEpochs - 1, Dig: lastInfo.dig, Sig: lastInfo.sig}
}

// getHist returns membership proofs for the history of versions
// up until the latest.
func getHist(keyMap *merkle.Tree, uid, numVers uint64, vrfSk *cryptoffi.VrfPrivateKey) []*ktserde.MembHide {
	if numVers == 0 {
		return nil
	}
	// latest registered ver not included in hist.
	var hist = make([]*ktserde.MembHide, 0, numVers-1)
	var ver = uint64(0)
	for ver < numVers-1 {
		label, labelProof := CompMapLabel(uid, ver, vrfSk)
		inMap, mapVal, mapProof := keyMap.Prove(label)
		std.Assert(inMap)
		hist = append(hist, &ktserde.MembHide{LabelProof: labelProof, MapVal: mapVal, MerkleProof: mapProof})
		ver++
	}
	return hist
}

// getLatest returns whether a version is registered, and if so,
// a membership proof for the latest version.
func getLatest(keyMap *merkle.Tree, uid, numVers uint64, vrfSk *cryptoffi.VrfPrivateKey, commitSecret, pk []byte) (bool, *ktserde.Memb) {
	if numVers == 0 {
		return false, &ktserde.Memb{PkOpen: &ktserde.CommitOpen{}}
	}
	label, labelProof := CompMapLabel(uid, numVers-1, vrfSk)
	inMap, mapVal, mapProof := keyMap.Prove(label)
	std.Assert(inMap)
	valPre, _, err1 := ktserde.MapValPreDecode(mapVal)
	std.Assert(!err1)
	r := compCommitOpen(commitSecret, label)
	open := &ktserde.CommitOpen{Val: pk, Rand: r}
	return true, &ktserde.Memb{LabelProof: labelProof, EpochAdded: valPre.Epoch, PkOpen: open, MerkleProof: mapProof}
}

// getBound returns a non-membership proof for the boundary version.
func getBound(keyMap *merkle.Tree, uid, numVers uint64, vrfSk *cryptoffi.VrfPrivateKey) *ktserde.NonMemb {
	label, labelProof := CompMapLabel(uid, numVers, vrfSk)
	inMap, _, mapProof := keyMap.Prove(label)
	std.Assert(!inMap)
	return &ktserde.NonMemb{LabelProof: labelProof, MerkleProof: mapProof}
}
