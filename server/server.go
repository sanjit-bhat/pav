package server

import (
	"sync"
	"time"

	"github.com/goose-lang/std"
	"github.com/sanjit-bhat/pav/cryptoffi"
	"github.com/sanjit-bhat/pav/hashchain"
	"github.com/sanjit-bhat/pav/ktcore"
	"github.com/sanjit-bhat/pav/merkle"
)

var (
	WorkQSize    int = 1024
	BatchSize    int = 128
	BatchTimeout     = time.Second
)

type Server struct {
	mu   *sync.RWMutex
	secs *secrets
	keys *keyStore
	hist *history
	// workQ for batch processing Put requests.
	workQ chan *Work
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

// Start bootstraps a party with knowledge of the last hash
// in the hashchain and vrf.
func (s *Server) Start() *StartReply {
	s.mu.RLock()
	defer s.mu.RUnlock()
	predLen := uint64(len(s.hist.audits)) - 1
	predLink, proof := s.hist.chain.Bootstrap()
	lastSig := s.hist.audits[predLen].LinkSig
	pk := s.secs.vrf.PublicKey()
	return &StartReply{PrevEpochLen: predLen, PrevLink: predLink, ChainProof: proof, LinkSig: lastSig, VrfPk: pk, VrfSig: s.hist.vrfPkSig}
}

// Put queues pk (at the specified version) for insertion.
func (s *Server) Put(uid uint64, pk []byte, ver uint64) {
	s.workQ <- &Work{Uid: uid, Pk: pk, Ver: ver}
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
	proof = append(proof, s.hist.audits[prevEpochLen:]...)
	return
}

type Work struct {
	Uid uint64
	Pk  []byte
	Ver uint64
	Err bool
}

type mapEntry struct {
	label []byte
	val   []byte
}

func (s *Server) worker() {
	for {
		work := getWork(s.workQ)
		if len(work) == 0 {
			continue
		}
		s.doWork(work)
	}
}

func getWork(workQ <-chan *Work) (work []*Work) {
	work = make([]*Work, 0, BatchSize)
	timer := time.NewTimer(BatchTimeout)

	// batch-aggregator with timeout.
	for i := 0; i < BatchSize; i++ {
		select {
		case job, ok := <-workQ:
			// never close channel.
			std.Assert(ok)
			work = append(work, job)
		case <-timer.C:
			return
		}
	}
	return
}

func (s *Server) doWork(work []*Work) {
	s.checkWork(work)

	// NOTE: for correctness, addEntries (write) must start with the same
	// state as makeEntries (read). we ensure this by not having any write
	// lockers outside this fn.
	ents := s.makeEntries(work)
	s.mu.Lock()
	s.addEntries(work, ents)
	s.mu.Unlock()
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
	wq := make(chan *Work, WorkQSize)
	s := &Server{mu: mu, secs: secs, keys: keys, hist: hist, workQ: wq}

	// commit empty map as epoch 0.
	dig := keys.hidden.Hash()
	link := chain.Append(dig)
	linkSig := ktcore.SignLink(s.secs.sig, 0, link)
	s.hist.audits = append(s.hist.audits, &ktcore.AuditProof{LinkSig: linkSig})

	go s.worker()
	return s, sigPk
}

func (s *Server) checkWork(work []*Work) {
	uidSet := make(map[uint64]bool, len(work))
	for _, w := range work {
		uid := w.Uid
		// error out wrong versions.
		nextVer := uint64(len(s.keys.plain[uid]))
		if w.Ver != nextVer {
			w.Err = true
			continue
		}
		// error out duplicate uid's. arbitrarily picks one to succeed.
		_, ok := uidSet[uid]
		if ok {
			w.Err = true
			continue
		}
		uidSet[uid] = false
	}
}

func (s *Server) makeEntries(work []*Work) (ents []*mapEntry) {
	ents = make([]*mapEntry, len(work))
	wg := new(sync.WaitGroup)
	for i := 0; i < len(work); i++ {
		job := work[i]
		if job.Err {
			continue
		}
		out := &mapEntry{}
		ents[i] = out
		wg.Add(1)
		go func() {
			s.makeEntry(job, out)
			wg.Done()
		}()
	}
	wg.Wait()
	return
}

func (s *Server) makeEntry(in *Work, out *mapEntry) {
	numVers := uint64(len(s.keys.plain[in.Uid]))
	mapLabel := ktcore.EvalMapLabel(s.secs.vrf, in.Uid, numVers)
	rand := ktcore.GetCommitRand(s.secs.commit, mapLabel)
	open := &ktcore.CommitOpen{Val: in.Pk, Rand: rand}
	mapVal := ktcore.GetMapVal(open)

	out.label = mapLabel
	out.val = mapVal
}

func (s *Server) addEntries(work []*Work, ents []*mapEntry) {
	upd := make([]*ktcore.UpdateProof, 0, len(work))
	for i := 0; i < len(work); i++ {
		job := work[i]
		if job.Err {
			continue
		}

		out := ents[i]
		label := out.label

		proof := s.keys.hidden.Put(label, out.val)
		s.keys.plain[job.Uid] = append(s.keys.plain[job.Uid], job.Pk)

		info := &ktcore.UpdateProof{MapLabel: label, MapVal: out.val, NonMembProof: proof}
		upd = append(upd, info)
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
		label, labelProof := ktcore.ProveMapLabel(s.secs.vrf, uid, ver)
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
	label, labelProof := ktcore.ProveMapLabel(s.secs.vrf, uid, numVers)
	inMap, _, mapProof := s.keys.hidden.Prove(label)
	std.Assert(!inMap)
	bound = &ktcore.NonMemb{LabelProof: labelProof, MerkleProof: mapProof}
	return
}
