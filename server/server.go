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

type Server struct {
	secs *secrets
	// workQ for batching puts into one epoch update.
	workQ     chan *work
	// epochTime (tunable) is the time between epoch updates.
	epochTime time.Duration

	mu   *sync.RWMutex
	keys *keyStore
	hist *history
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
	// audits has auditing info for all epochs.
	// for epoch 0, the UpdateProof is invalid (there is no prior epoch),
	// but [Server.Audit] will never return it.
	audits   []*ktcore.AuditProof
	vrfPkSig []byte
}

// Start bootstraps a party with knowledge of the last hash
// in the hashchain and vrf.
func (s *Server) Start() (chain *StartChain, vrf *StartVrf) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	predLen := uint64(len(s.hist.audits)) - 1
	predLink, proof := s.hist.chain.Bootstrap()
	lastSig := s.hist.audits[predLen].LinkSig
	pk := s.secs.vrf.PublicKey()
	chain = &StartChain{PrevEpochLen: predLen, PrevLink: predLink, ChainProof: proof, LinkSig: lastSig}
	vrf = &StartVrf{VrfPk: pk, VrfSig: s.hist.vrfPkSig}
	return
}

// Put queues pk (at the specified version) for insertion.
func (s *Server) Put(uid uint64, ver uint64, pk []byte) {
	label := ktcore.EvalMapLabel(s.secs.vrf, uid, ver)
	rand := ktcore.GetCommitRand(s.secs.commit, label)
	val := ktcore.GetMapVal(pk, rand)
	s.workQ <- &work{uid: uid, ver: ver, pk: pk, mapLabel: label, mapVal: val}
}

// History gives key history for uid, excluding first prevVerLen versions.
// the caller already saw prevEpoch.
func (s *Server) History(uid, prevEpoch, prevVerLen uint64) (chainProof, linkSig []byte, hist []*ktcore.Memb, bound *ktcore.NonMemb, err bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	numEps := uint64(len(s.hist.audits))
	if prevEpoch >= numEps {
		err = true
		return
	}
	numVers := uint64(len(s.keys.plain[uid]))
	if prevVerLen > numVers {
		err = true
		return
	}

	chainProof = s.hist.chain.Prove(prevEpoch + 1)
	linkSig = s.hist.audits[len(s.hist.audits)-1].LinkSig
	hist = s.getHist(uid, prevVerLen)
	bound = s.getBound(uid, numVers)
	return
}

// Audit errors if args out of bounds.
func (s *Server) Audit(prevEpoch uint64) (proof []*ktcore.AuditProof, err bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	numEps := uint64(len(s.hist.audits))
	if prevEpoch >= numEps {
		err = true
		return
	}
	proof = append(proof, s.hist.audits[prevEpoch+1:]...)
	return
}

type work struct {
	// the original Put request.
	uid uint64
	ver uint64
	pk  []byte

	// the computed merkle map entry.
	mapLabel []byte
	mapVal   []byte
}

func (s *Server) worker() {
	// our merkle tree only supports one latest view, so merkle updates
	// must be sync'd with epoch releases. we batch updates for perf.
	for {
		w := s.getWork()
		// empty batches are safe, but for perf, skip them.
		if len(w) == 0 {
			continue
		}
		s.doWork(w)
	}
}

// New starts a [Server] with epochTime, the time between epochs.
// AKD uses an epochTime of ~1 second.
func New(epochTime time.Duration) (*Server, cryptoffi.SigPublicKey) {
	mu := new(sync.RWMutex)
	vrfSk := cryptoffi.VrfGenerateKey()
	sigPk, sigSk := cryptoffi.SigGenerateKey()
	vrfSig := ktcore.SignVrf(sigSk, vrfSk.PublicKey())
	commitSec := cryptoffi.RandBytes(cryptoffi.HashLen)
	secs := &secrets{sig: sigSk, vrf: vrfSk, commit: commitSec}
	hidden := &merkle.Map{}
	plain := make(map[uint64][][]byte)
	keys := &keyStore{hidden: hidden, plain: plain}
	chain := hashchain.New()
	hist := &history{chain: chain, vrfPkSig: vrfSig}
	wq := make(chan *work)
	s := &Server{secs: secs, workQ: wq, epochTime: epochTime, mu: mu, keys: keys, hist: hist}

	// commit empty map as epoch 0 to always have some epoch
	// against which we can respond to requests.
	dig := keys.hidden.Hash()
	link := chain.Append(dig)
	linkSig := ktcore.SignLink(s.secs.sig, 0, link)
	s.hist.audits = append(s.hist.audits, &ktcore.AuditProof{LinkSig: linkSig})

	go s.worker()
	return s, sigPk
}

func (s *Server) getWork() (work []*work) {
	timer := time.NewTimer(s.epochTime)
	// don't care about upper-bounding batch size.
	// so aggregate as much work as we can within epochTime.
	for {
		select {
		case <-timer.C:
			return
		case w := <-s.workQ:
			work = append(work, w)
		}
	}
}

func (s *Server) doWork(work []*work) {
	s.mu.Lock()
	defer s.mu.Unlock()
	upd := make([]*ktcore.UpdateProof, 0, len(work))
	for _, w := range work {
		// check: for each uid, maintain contiguous seq of versions.
		nextVer := uint64(len(s.keys.plain[w.uid]))
		if w.ver != nextVer {
			continue
		}

		// update.
		proof := s.keys.hidden.Put(w.mapLabel, w.mapVal)
		s.keys.plain[w.uid] = append(s.keys.plain[w.uid], w.pk)
		info := &ktcore.UpdateProof{MapLabel: w.mapLabel, MapVal: w.mapVal, NonMembProof: proof}
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
	hist = make([]*ktcore.Memb, 0, numVers-prefixLen)
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
