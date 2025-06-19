package server

import (
	"sync"

	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/hashchain"
	"github.com/mit-pdos/pav/ktcore"
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
	// chain is a hashchain of merkle digests across the epochs.
	chain *hashchain.HashChain
	// auditHist stores auditing info on prior epochs.
	auditHist []*ktcore.AuditProof
	vrfPkSig  []byte
	// WorkQ batch processes Put requests.
	WorkQ *WorkQ
}

// Start bootstraps a party with knowledge of the hashchain and vrf.
func (s *Server) Start() *StartReply {
	s.mu.RLock()
	predLen := uint64(len(s.auditHist)) - 1
	predLink, proof := s.chain.ProveLast()
	lastSig := s.auditHist[predLen].LinkSig
	pk := s.vrfSk.PublicKey()
	s.mu.RUnlock()
	return &StartReply{StartEpochLen: predLen, StartLink: predLink, ChainProof: proof, LinkSig: lastSig, VrfPk: pk, VrfSig: s.vrfPkSig}
}

// Put queues pk (at the specified version) for insertion.
func (s *Server) Put(uid uint64, pk []byte, ver uint64) {
	// NOTE: this doesn't need to block.
	s.WorkQ.Do(&WQReq{Uid: uid, Pk: pk, Ver: ver})
}

// History gives key history for uid, excluding first prevVerLen versions.
// the caller already saw prevEpoch.
func (s *Server) History(uid, prevEpoch, prevVerLen uint64) ([]byte, []byte, []*ktcore.Memb, *ktcore.NonMemb, bool) {
	s.mu.RLock()
	numEps := uint64(len(s.auditHist))
	if prevEpoch >= numEps {
		s.mu.RUnlock()
		return nil, nil, nil, nil, true
	}
	numVers := uint64(len(s.plainPks[uid]))
	if prevVerLen > numVers {
		s.mu.RUnlock()
		return nil, nil, nil, nil, true
	}

	epochProof := s.chain.Prove(prevEpoch + 1)
	sig := s.auditHist[len(s.auditHist)-1].LinkSig
	hist := s.getHist(uid, prevVerLen)
	bound := s.getBound(uid, numVers)
	s.mu.RUnlock()

	if prevEpoch+1 == numEps {
		// client already saw sig. don't send.
		return epochProof, nil, hist, bound, false
	}
	return epochProof, sig, hist, bound, false
}

// Audit returns an err on fail.
func (s *Server) Audit(epoch uint64) (*ktcore.AuditProof, bool) {
	s.mu.RLock()
	if epoch >= uint64(len(s.auditHist)) {
		s.mu.RUnlock()
		return &ktcore.AuditProof{}, true
	}
	proof := s.auditHist[epoch]
	s.mu.RUnlock()
	return proof, false
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

func New() (*Server, cryptoffi.SigPublicKey) {
	mu := new(sync.RWMutex)
	sigPk, sigSk := cryptoffi.SigGenerateKey()
	vrfSk := cryptoffi.VrfGenerateKey()
	vrfSig := ktcore.SignVrf(sigSk, vrfSk.PublicKey())
	secret := cryptoffi.RandBytes(cryptoffi.HashLen)
	keys := merkle.New()
	plainPks := make(map[uint64][][]byte)
	chain := hashchain.New()
	wq := NewWorkQ()
	s := &Server{mu: mu, sigSk: sigSk, vrfSk: vrfSk, commitSecret: secret, keyMap: keys, plainPks: plainPks, chain: chain, vrfPkSig: vrfSig, WorkQ: wq}

	// commit empty tree as epoch 0.
	dig := keys.Digest()
	link := chain.Append(dig)
	linkSig := ktcore.SignLink(s.sigSk, 0, link)
	s.auditHist = append(s.auditHist, &ktcore.AuditProof{LinkSig: linkSig})

	go func() {
		for {
			s.Worker()
		}
	}()
	return s, sigPk
}

func getCommitRand(secret, label []byte) []byte {
	hr := cryptoffi.NewHasher()
	hr.Write(secret)
	hr.Write(label)
	return hr.Sum(nil)
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
	mapLabel := ktcore.EvalMapLabel(in.Uid, numVers, s.vrfSk)
	rand := getCommitRand(s.commitSecret, mapLabel)
	open := &ktcore.CommitOpen{Val: in.Pk, Rand: rand}
	mapVal := ktcore.GetMapVal(open)

	out.label = mapLabel
	out.val = mapVal
}

func (s *Server) addEntries(work []*Work, ents []*mapEntry) {
	upd := make([]*ktcore.UpdateProof, 0, len(work))
	var i = uint64(0)
	for i < uint64(len(work)) {
		resp := work[i].Resp
		if !resp.Err {
			req := work[i].Req
			out0 := ents[i]
			label := out0.label

			inTree, _, proof := s.keyMap.Prove(label)
			std.Assert(!inTree)
			info := &ktcore.UpdateProof{MapLabel: label, MapVal: out0.val, NonMembProof: proof}
			upd = append(upd, info)

			err0 := s.keyMap.Put(label, out0.val)
			std.Assert(!err0)
			s.plainPks[req.Uid] = append(s.plainPks[req.Uid], req.Pk)
		}
		i++
	}

	dig := s.keyMap.Digest()
	link := s.chain.Append(dig)
	epoch := uint64(len(s.auditHist))
	sig := ktcore.SignLink(s.sigSk, epoch, link)
	s.auditHist = append(s.auditHist, &ktcore.AuditProof{Updates: upd, LinkSig: sig})
}

// getHist returns a history of membership proofs for all post-prefix versions.
func (s *Server) getHist(uid, prefixLen uint64) []*ktcore.Memb {
	pks := s.plainPks[uid]
	numVers := uint64(len(pks))
	var hist []*ktcore.Memb
	var ver = prefixLen
	for ver < numVers {
		label, labelProof := ktcore.ProveMapLabel(uid, ver, s.vrfSk)
		inMap, _, mapProof := s.keyMap.Prove(label)
		std.Assert(inMap)
		rand := getCommitRand(s.commitSecret, label)
		open := &ktcore.CommitOpen{Val: pks[ver], Rand: rand}
		memb := &ktcore.Memb{LabelProof: labelProof, PkOpen: open, MerkleProof: mapProof}
		hist = append(hist, memb)
		ver++
	}
	return hist
}

// getBound returns a non-membership proof for the boundary version.
func (s *Server) getBound(uid, numVers uint64) *ktcore.NonMemb {
	label, labelProof := ktcore.ProveMapLabel(uid, numVers, s.vrfSk)
	inMap, _, mapProof := s.keyMap.Prove(label)
	std.Assert(!inMap)
	return &ktcore.NonMemb{LabelProof: labelProof, MerkleProof: mapProof}
}
