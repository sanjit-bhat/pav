package server

import (
	"sync"

	"github.com/goose-lang/std"
	"github.com/sanjit-bhat/pav/cryptoffi"
	"github.com/sanjit-bhat/pav/hashchain"
	"github.com/sanjit-bhat/pav/ktcore"
	"github.com/sanjit-bhat/pav/merkle"
)

type Server struct {
	mu   *sync.RWMutex
	secs *secrets
	keys *keyStore
	hist *history
	// workQ batch processes Put requests.
	workQ *WorkQ
}

type secrets struct {
	sig *cryptoffi.SigPrivateKey
	vrf *cryptoffi.VrfPrivateKey
	// commit is the 32-byte secret used to generate commitments.
	commit []byte
}

type keyStore struct {
	// hidden stores (mapLabel, mapVal) entries, see [ktcore].
	hidden *merkle.Map
	// plain stores plaintext mappings from uid to pks.
	plain map[uint64][][]byte
}

type history struct {
	// chain is a hashchain of merkle digests across the epochs.
	chain *hashchain.HashChain
	// audits has auditing proofs on prior epochs.
	audits   []*ktcore.AuditProof
	vrfPkSig []byte
}

// Start bootstraps a party with knowledge of the hashchain and vrf.
func (s *Server) Start() *StartReply {
	s.mu.RLock()
	defer s.mu.RUnlock()
	predLen := uint64(len(s.hist.audits)) - 1
	predLink, proof := s.hist.chain.Bootstrap()
	lastSig := s.hist.audits[predLen].LinkSig
	pk := s.secs.vrf.PublicKey()
	return &StartReply{StartEpochLen: predLen, StartLink: predLink, ChainProof: proof, LinkSig: lastSig, VrfPk: pk, VrfSig: s.hist.vrfPkSig}
}

// Put queues pk (at the specified version) for insertion.
func (s *Server) Put(uid uint64, pk []byte, ver uint64) {
	// NOTE: this doesn't need to block.
	s.workQ.Do(&WQReq{Uid: uid, Pk: pk, Ver: ver})
}

// History gives key history for uid, excluding first prevVerLen versions.
// the caller already saw prevEpoch.
func (s *Server) History(uid, prevEpoch, prevVerLen uint64) (chainProof, linkSig []byte, hist []*ktcore.Memb, bound *ktcore.NonMemb, err ktcore.Blame) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	numEps := uint64(len(s.hist.audits))
	if prevEpoch >= numEps {
		err = ktcore.BlameUnknown
		return
	}
	numVers := uint64(len(s.keys.plain[uid]))
	if prevVerLen > numVers {
		err = ktcore.BlameUnknown
		return
	}

	chainProof = s.hist.chain.Prove(prevEpoch + 1)
	linkSig = s.hist.audits[len(s.hist.audits)-1].LinkSig
	hist = s.getHist(uid, prevVerLen)
	bound = s.getBound(uid, numVers)

	if prevEpoch+1 == numEps {
		// client already saw sig. don't send.
		linkSig = nil
		return
	}
	return
}

// Audit errors if args out of bounds.
func (s *Server) Audit(prevEpochLen uint64) (proof []*ktcore.AuditProof, err ktcore.Blame) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	numEps := uint64(len(s.hist.audits))
	if prevEpochLen > numEps {
		err = ktcore.BlameUnknown
		return
	}

	for ep := prevEpochLen; ep < numEps; ep++ {
		proof = append(proof, s.hist.audits[ep])
	}
	return
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

func (s *Server) worker() {
	work := s.workQ.Get()
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
	commitSec := cryptoffi.RandBytes(cryptoffi.HashLen)
	secs := &secrets{sig: sigSk, vrf: vrfSk, commit: commitSec}
	hidden := &merkle.Map{}
	plain := make(map[uint64][][]byte)
	keys := &keyStore{hidden: hidden, plain: plain}
	chain := hashchain.New()
	hist := &history{chain: chain, vrfPkSig: vrfSig}
	wq := NewWorkQ()
	s := &Server{mu: mu, secs: secs, keys: keys, hist: hist, workQ: wq}

	// commit empty map as epoch 0.
	dig := keys.hidden.Hash()
	link := chain.Append(dig)
	linkSig := ktcore.SignLink(s.secs.sig, 0, link)
	s.hist.audits = append(s.hist.audits, &ktcore.AuditProof{LinkSig: linkSig})

	go func() {
		for {
			s.worker()
		}
	}()
	return s, sigPk
}

func (s *Server) checkRequests(work []*Work) {
	uidSet := make(map[uint64]bool, len(work))
	for _, w := range work {
		w.Resp = &WQResp{}
		uid := w.Req.Uid
		// error out wrong versions.
		nextVer := uint64(len(s.keys.plain[uid]))
		if w.Req.Ver != nextVer {
			w.Resp.Err = true
			continue
		}
		// error out duplicate uid's. arbitrarily picks one to succeed.
		_, ok := uidSet[uid]
		if ok {
			w.Resp.Err = true
			continue
		}
		uidSet[uid] = false
	}
}

func (s *Server) makeEntries(work []*Work) []*mapEntry {
	ents := make([]*mapEntry, len(work))
	for i := uint64(0); i < uint64(len(work)); i++ {
		ents[i] = &mapEntry{}
	}
	wg := new(sync.WaitGroup)
	for i := uint64(0); i < uint64(len(work)); i++ {
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
	}
	wg.Wait()
	return ents
}

func (s *Server) makeEntry(in *WQReq, out *mapEntry) {
	numVers := uint64(len(s.keys.plain[in.Uid]))
	mapLabel := ktcore.EvalMapLabel(in.Uid, numVers, s.secs.vrf)
	rand := ktcore.GetCommitRand(s.secs.commit, mapLabel)
	open := &ktcore.CommitOpen{Val: in.Pk, Rand: rand}
	mapVal := ktcore.GetMapVal(open)

	out.label = mapLabel
	out.val = mapVal
}

func (s *Server) addEntries(work []*Work, ents []*mapEntry) {
	upd := make([]*ktcore.UpdateProof, 0, len(work))
	for i := uint64(0); i < uint64(len(work)); i++ {
		resp := work[i].Resp
		if !resp.Err {
			req := work[i].Req
			out0 := ents[i]
			label := out0.label

			proof := s.keys.hidden.Put(label, out0.val)
			s.keys.plain[req.Uid] = append(s.keys.plain[req.Uid], req.Pk)

			info := &ktcore.UpdateProof{MapLabel: label, MapVal: out0.val, NonMembProof: proof}
			upd = append(upd, info)
		}
	}

	dig := s.keys.hidden.Hash()
	link := s.hist.chain.Append(dig)
	epoch := uint64(len(s.hist.audits))
	sig := ktcore.SignLink(s.secs.sig, epoch, link)
	s.hist.audits = append(s.hist.audits, &ktcore.AuditProof{Updates: upd, LinkSig: sig})
}

// getHist returns a history of membership proofs for all post-prefix versions.
func (s *Server) getHist(uid, prefixLen uint64) (hist []*ktcore.Memb) {
	pks := s.keys.plain[uid]
	numVers := uint64(len(pks))
	for ver := prefixLen; ver < numVers; ver++ {
		label, labelProof := ktcore.ProveMapLabel(uid, ver, s.secs.vrf)
		inMap, _, mapProof := s.keys.hidden.Prove(label)
		std.Assert(inMap)
		rand := ktcore.GetCommitRand(s.secs.commit, label)
		open := &ktcore.CommitOpen{Val: pks[ver], Rand: rand}
		memb := &ktcore.Memb{LabelProof: labelProof, PkOpen: open, MerkleProof: mapProof}
		hist = append(hist, memb)
	}
	return
}

// getBound returns a non-membership proof for the boundary version.
func (s *Server) getBound(uid, numVers uint64) (bound *ktcore.NonMemb) {
	label, labelProof := ktcore.ProveMapLabel(uid, numVers, s.secs.vrf)
	inMap, _, mapProof := s.keys.hidden.Prove(label)
	std.Assert(!inMap)
	bound = &ktcore.NonMemb{LabelProof: labelProof, MerkleProof: mapProof}
	return
}
