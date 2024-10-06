package kt2

import (
	"github.com/goose-lang/primitive"
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/merkle"
	"sync"
)

// compMapLabel rets mapLabel (VRF(uid || ver)) and a VRF proof.
func compMapLabel(uid uint64, ver uint64, sk *cryptoffi.VRFPrivateKey) ([]byte, []byte) {
	l := &MapLabelPre{Uid: uid, Ver: ver}
	lByt := MapLabelPreEncode(make([]byte, 0), l)
	h, p := sk.Hash(lByt)
	return h, p
}

// compMapVal rets mapVal (epoch || commitment) and a commitment opening,
// where commitment = Hash(pk || randBytes).
func compMapVal(epoch uint64, pk []byte) ([]byte, *PkCommOpen) {
	// from 8.12 of [Boneh-Shoup] v0.6, a 512-bit rand space provides statistical
	// hiding for this sha256-based commitment scheme.
	// [Boneh-Shoup]: https://toc.cryptobook.us
	r := cryptoffi.RandBytes(2 * cryptoffi.HashLen)
	open := &PkCommOpen{Pk: pk, R: r}
	openByt := PkCommOpenEncode(make([]byte, 0), open)
	comm := cryptoffi.Hash(openByt)
	v := &MapValPre{Epoch: epoch, PkComm: comm}
	vByt := MapValPreEncode(make([]byte, 0), v)
	return vByt, open
}

type servEpochInfo struct {
	// updates stores (mapLabel, mapVal) keyMap updates.
	updates map[string][]byte
	dig     []byte
	sig     []byte
}

type Server struct {
	mu    *sync.Mutex
	sigSk cryptoffi.PrivateKey
	vrfSk *cryptoffi.VRFPrivateKey
	// keyMap stores (mapLabel, mapVal) entries.
	keyMap *merkle.Tree
	// histInfo stores info about prior epochs.
	histInfo []*servEpochInfo
	// pkCommOpens stores pk commitment openings for a particular mapLabel.
	pkCommOpens map[string]*PkCommOpen
	// nextVers stores next version #'s for a particular uid.
	nextVers map[uint64]uint64
}

// getMemb pre-cond that (uid, ver) in-bounds.
func (s *Server) getMemb(uid, ver uint64) *MembProof {
	label, vrfProof := compMapLabel(uid, ver, s.vrfSk)
	getReply := s.keyMap.Get(label)
	primitive.Assert(!getReply.Error)
	primitive.Assert(getReply.ProofTy)
	valPre, _, err0 := MapValPreDecode(getReply.Val)
	primitive.Assert(!err0)
	open, ok0 := s.pkCommOpens[string(label)]
	primitive.Assert(ok0)
	return &MembProof{Label: label, VrfProof: vrfProof, EpochAdded: valPre.Epoch, CommOpen: open, MerkProof: getReply.Proof}
}

func (s *Server) getHist(uid uint64) []*MembProof {
	var membs []*MembProof
	nextVer := s.nextVers[uid]
	for ver := uint64(0); ver < nextVer; ver++ {
		membs = append(membs, s.getMemb(uid, ver))
	}
	return membs
}

// getLatest pre-cond that uid has some versions.
func (s *Server) getLatest(uid uint64) *MembProof {
	nextVer := s.nextVers[uid]
	primitive.Assert(nextVer != 0)
	latVer := nextVer - 1
	return s.getMemb(uid, latVer)
}

func (s *Server) getBound(uid uint64) *NonMembProof {
	nextVer := s.nextVers[uid]
	nextLabel, nextVrfProof := compMapLabel(uid, nextVer, s.vrfSk)
	nextReply := s.keyMap.Get(nextLabel)
	primitive.Assert(!nextReply.Error)
	primitive.Assert(!nextReply.ProofTy)
	return &NonMembProof{Label: nextLabel, VrfProof: nextVrfProof, MerkProof: nextReply.Proof}
}

func (s *Server) getDig() *SigDig {
	numEpochs := uint64(len(s.histInfo))
	lastInfo := s.histInfo[numEpochs-1]
	return &SigDig{Epoch: numEpochs - 1, Dig: lastInfo.dig, Sig: lastInfo.sig}
}

func (s *Server) Put(uid uint64, pk []byte) (*SigDig, *MembProof, *NonMembProof) {
	s.mu.Lock()
	// add to key map.
	ver, _ := s.nextVers[uid]
	label, _ := compMapLabel(uid, ver, s.vrfSk)
	nextEpoch := uint64(len(s.histInfo))
	val, open := compMapVal(nextEpoch, pk)
	dig, _, err0 := s.keyMap.Put(label, val)
	primitive.Assert(!err0)

	// update supporting stores.
	s.pkCommOpens[string(label)] = open
	// assume OOM before running out of versions.
	s.nextVers[uid] = std.SumAssumeNoOverflow(ver, 1)

	// sign new dig.
	updates := make(map[string][]byte)
	updates[string(label)] = val
	preSig := &PreSigDig{Epoch: nextEpoch, Dig: dig}
	preSigByt := PreSigDigEncode(make([]byte, 0), preSig)
	sig := s.sigSk.Sign(preSigByt)
	newInfo := &servEpochInfo{updates: updates, dig: dig, sig: sig}
	s.histInfo = append(s.histInfo, newInfo)

	// get proofs.
	sigDig := s.getDig()
	latest := s.getLatest(uid)
	bound := s.getBound(uid)
	s.mu.Unlock()
	return sigDig, latest, bound
}

func (s *Server) Get(uid uint64) (*SigDig, []*MembProof, *NonMembProof) {
	s.mu.Lock()
	dig := s.getDig()
	hist := s.getHist(uid)
	bound := s.getBound(uid)
	s.mu.Unlock()
	return dig, hist, bound
}

func (s *Server) SelfMon(uid uint64) (*SigDig, *NonMembProof) {
	s.mu.Lock()
	dig := s.getDig()
	bound := s.getBound(uid)
	s.mu.Unlock()
	return dig, bound
}

// Audit returns an err on fail.
func (s *Server) Audit(epoch uint64) (*UpdateProof, bool) {
	s.mu.Lock()
	if epoch >= uint64(len(s.histInfo)) {
		s.mu.Unlock()
		return nil, true
	}
	info := s.histInfo[epoch]
	s.mu.Unlock()
	p := &UpdateProof{Updates: info.updates, Sig: info.sig}
	return p, false
}

func newServer() (*Server, cryptoffi.PublicKey, *cryptoffi.VRFPublicKey) {
	mu := new(sync.Mutex)
	sigPk, sigSk := cryptoffi.GenerateKey()
	vrfPk, vrfSk := cryptoffi.VRFGenerateKey()
	m := &merkle.Tree{}
	opens := make(map[string]*PkCommOpen)
	vers := make(map[uint64]uint64)
	return &Server{mu: mu, sigSk: sigSk, vrfSk: vrfSk, keyMap: m, pkCommOpens: opens, nextVers: vers}, sigPk, vrfPk
}
