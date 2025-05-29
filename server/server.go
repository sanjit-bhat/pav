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
	// plainPks stores all plaintext pks, whereas keyMap only has commitments.
	// its length is the number of registered versions.
	plainPks map[uint64][][]byte
	// epochHist stores info about prior epochs, for auditing.
	epochHist []*servEpochInfo
	// WorkQ batch processes Put requests.
	WorkQ *WorkQ
}

type servEpochInfo struct {
	// updates stores (mapLabel, mapVal) keyMap updates.
	updates map[string][]byte
	dig     []byte
	sig     []byte
}

// Put queues pk (at the specified version) for insertion.
func (s *Server) Put(uid uint64, pk []byte, ver uint64) {
	// NOTE: this doesn't need to block.
	s.WorkQ.Do(&WQReq{Uid: uid, Pk: pk, Ver: ver})
}

// History excludes the first prefixLen versions.
func (s *Server) History(uid uint64, prefixLen uint64) (*ktserde.SigDig, []*ktserde.Memb, *ktserde.NonMemb, bool) {
	s.mu.RLock()
	numVers := uint64(len(s.plainPks[uid]))
	if prefixLen > numVers {
		s.mu.RUnlock()
		return nil, nil, nil, true
	}

	dig := s.getDig()
	hist := s.getHist(uid, prefixLen)
	bound := s.getBound(uid, numVers)
	s.mu.RUnlock()
	return dig, hist, bound, false
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

type mapEntry struct {
	label []byte
	val   []byte
}

func (s *Server) Worker() {
	work := s.WorkQ.Get()
	s.checkRequests(work)

	// NOTE: for correctness, addEntries (write) must start with the same
	// state as makeEntries (read). we ensure this by not having any write
	// lockers outside this fn.
	ents := s.makeEntries(work)
	s.mu.Lock()
	s.addEntries(work, ents)
	s.mu.Unlock()

	for _, w := range work {
		w.Finish()
	}
}

func NewServer() (*Server, cryptoffi.SigPublicKey, *cryptoffi.VrfPublicKey) {
	mu := new(sync.RWMutex)
	sigPk, sigSk := cryptoffi.SigGenerateKey()
	vrfPk, vrfSk := cryptoffi.VrfGenerateKey()
	secret := cryptoffi.RandBytes(cryptoffi.HashLen)
	keys := merkle.NewTree()
	plainPks := make(map[uint64][][]byte)
	var hist []*servEpochInfo
	// commit empty tree as init epoch.
	wq := NewWorkQ()
	s := &Server{mu: mu, sigSk: sigSk, vrfSk: vrfSk, commitSecret: secret, keyMap: keys, plainPks: plainPks, epochHist: hist, WorkQ: wq}
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

func (s *Server) checkRequests(work []*Work) {
	uidSet := make(map[uint64]bool, len(work))
	for _, w := range work {
		w.Resp = &WQResp{}
		uid := w.Req.Uid
		ver := w.Req.Ver

		// error out wrong versions.
		nextVer := uint64(len(s.plainPks[uid]))
		if ver != nextVer {
			w.Resp.Err = true
			continue
		}

		// error out duplicate uid's. arbitrarily picks one to succeed.
		_, ok := uidSet[uid]
		if ok {
			w.Resp.Err = true
		} else {
			uidSet[uid] = false
		}
	}
}

func (s *Server) makeEntries(work []*Work) []*mapEntry {
	ents := make([]*mapEntry, len(work))
	var i uint64
	for i < uint64(len(work)) {
		ents[i] = &mapEntry{}
		i++
	}
	wg := new(sync.WaitGroup)
	i = 0
	for i < uint64(len(work)) {
		resp := work[i].Resp
		if !resp.Err {
			req := work[i].Req
			out := ents[i]
			wg.Add(1)
			go func() {
				s.makeEntry(req, out)
				wg.Done()
			}()
		}
		i++
	}
	wg.Wait()
	return ents
}

func (s *Server) makeEntry(in *WQReq, out *mapEntry) {
	numVers := uint64(len(s.plainPks[in.Uid]))
	mapLabel, _ := CompMapLabel(in.Uid, numVers, s.vrfSk)

	nextEpoch := uint64(len(s.epochHist))
	rand := compCommitOpen(s.commitSecret, mapLabel)
	open := &ktserde.CommitOpen{Val: in.Pk, Rand: rand}
	mapVal := CompMapVal(nextEpoch, open)

	out.label = mapLabel
	out.val = mapVal
}

func (s *Server) addEntries(work []*Work, ents []*mapEntry) {
	upd := make(map[string][]byte, len(work))
	var i = uint64(0)
	for i < uint64(len(work)) {
		resp := work[i].Resp
		if !resp.Err {
			req := work[i].Req
			out0 := ents[i]
			label := out0.label

			err0 := s.keyMap.Put(label, out0.val)
			std.Assert(!err0)
			upd[string(label)] = out0.val
			s.plainPks[req.Uid] = append(s.plainPks[req.Uid], req.Pk)
		}
		i++
	}
	s.updEpochHist(upd)
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

func (s *Server) getDig() *ktserde.SigDig {
	numEpochs := uint64(len(s.epochHist))
	lastInfo := s.epochHist[numEpochs-1]
	return &ktserde.SigDig{Epoch: numEpochs - 1, Dig: lastInfo.dig, Sig: lastInfo.sig}
}

// getHist returns a history of membership proofs for all post-prefix versions.
func (s *Server) getHist(uid, prefixLen uint64) []*ktserde.Memb {
	pks := s.plainPks[uid]
	numVers := uint64(len(pks))
	var hist []*ktserde.Memb
	var ver = prefixLen
	for ver < numVers {
		label, labelProof := CompMapLabel(uid, ver, s.vrfSk)
		inMap, mapVal, mapProof := s.keyMap.Prove(label)
		std.Assert(inMap)
		valPre, _, err0 := ktserde.MapValPreDecode(mapVal)
		std.Assert(!err0)
		rand := compCommitOpen(s.commitSecret, label)
		open := &ktserde.CommitOpen{Val: pks[ver], Rand: rand}
		memb := &ktserde.Memb{LabelProof: labelProof, EpochAdded: valPre.Epoch, PkOpen: open, MerkleProof: mapProof}
		hist = append(hist, memb)
		ver++
	}
	return hist
}

// getBound returns a non-membership proof for the boundary version.
func (s *Server) getBound(uid, numVers uint64) *ktserde.NonMemb {
	label, labelProof := CompMapLabel(uid, numVers, s.vrfSk)
	inMap, _, mapProof := s.keyMap.Prove(label)
	std.Assert(!inMap)
	return &ktserde.NonMemb{LabelProof: labelProof, MerkleProof: mapProof}
}
