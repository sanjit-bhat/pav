package kt

import (
	"github.com/goose-lang/primitive"
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/merkle"
	"sync"
)

// compMapLabel rets mapLabel (VRF(uid || ver)) and a VRF proof.
func compMapLabel(uid uint64, ver uint64, sk *cryptoffi.VrfPrivateKey) ([]byte, []byte) {
	l := &MapLabelPre{Uid: uid, Ver: ver}
	lByt := MapLabelPreEncode(make([]byte, 0), l)
	h, p := sk.Hash(lByt)
	return h, p
}

func compMapVal(epoch uint64, open *PkCommOpen) []byte {
	openByt := PkCommOpenEncode(make([]byte, 0), open)
	comm := cryptoffi.Hash(openByt)
	v := &MapValPre{Epoch: epoch, PkComm: comm}
	vByt := MapValPreEncode(make([]byte, 0), v)
	return vByt
}

// genValComm rets mapVal (epoch || commitment) and a commitment opening,
// where commitment = Hash(pk || randBytes).
func genValComm(epoch uint64, pk []byte) ([]byte, *PkCommOpen) {
	// from 8.12 of [Boneh-Shoup] v0.6, a 512-bit rand space provides statistical
	// hiding for this sha256-based commitment scheme.
	// [Boneh-Shoup]: https://toc.cryptobook.us
	r := cryptoffi.RandBytes(2 * cryptoffi.HashLen)
	open := &PkCommOpen{Pk: pk, R: r}
	return compMapVal(epoch, open), open
}

type servEpochInfo struct {
	// updates stores (mapLabel, mapVal) keyMap updates.
	updates map[string][]byte
	dig     []byte
	sig     []byte
}

type Server struct {
	mu    *sync.Mutex
	sigSk *cryptoffi.SigPrivateKey
	vrfSk *cryptoffi.VrfPrivateKey
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
func (s *Server) getMemb(uid, ver uint64) *Memb {
	// VRF is determ, so get same label as prev runs.
	label, vrfProof := compMapLabel(uid, ver, s.vrfSk)
	getReply := s.keyMap.Get(label)
	primitive.Assert(!getReply.Error)
	primitive.Assert(getReply.ProofTy)
	valPre, _, err0 := MapValPreDecode(getReply.Val)
	primitive.Assert(!err0)
	open, ok0 := s.pkCommOpens[string(label)]
	primitive.Assert(ok0)
	return &Memb{LabelProof: vrfProof, EpochAdded: valPre.Epoch, CommOpen: open, MerkProof: getReply.Proof}
}

// getMembHide pre-cond that (uid, ver) in-bounds.
func (s *Server) getMembHide(uid, ver uint64) *MembHide {
	label, vrfProof := compMapLabel(uid, ver, s.vrfSk)
	getReply := s.keyMap.Get(label)
	primitive.Assert(!getReply.Error)
	primitive.Assert(getReply.ProofTy)
	return &MembHide{LabelProof: vrfProof, MapVal: getReply.Val, MerkProof: getReply.Proof}
}

func (s *Server) getHist(uid uint64) []*MembHide {
	var membs []*MembHide
	nextVer := s.nextVers[uid]
	if nextVer == 0 {
		return membs
	}
	latVer := nextVer - 1
	for ver := uint64(0); ver < latVer; ver++ {
		membs = append(membs, s.getMembHide(uid, ver))
	}
	return membs
}

// getLatest pre-cond that uid has some versions.
func (s *Server) getLatest(uid uint64) *Memb {
	nextVer := s.nextVers[uid]
	primitive.Assert(nextVer != 0)
	latVer := nextVer - 1
	return s.getMemb(uid, latVer)
}

func (s *Server) getBound(uid uint64) *NonMemb {
	nextVer := s.nextVers[uid]
	nextLabel, nextVrfProof := compMapLabel(uid, nextVer, s.vrfSk)
	nextReply := s.keyMap.Get(nextLabel)
	primitive.Assert(!nextReply.Error)
	primitive.Assert(!nextReply.ProofTy)
	return &NonMemb{LabelProof: nextVrfProof, MerkProof: nextReply.Proof}
}

func (s *Server) getDig() *SigDig {
	numEpochs := uint64(len(s.histInfo))
	lastInfo := s.histInfo[numEpochs-1]
	return &SigDig{Epoch: numEpochs - 1, Dig: lastInfo.dig, Sig: lastInfo.sig}
}

func (s *Server) Put(uid uint64, pk []byte) (*SigDig, *Memb, *NonMemb) {
	s.mu.Lock()
	// add to key map.
	ver := s.nextVers[uid]
	label, _ := compMapLabel(uid, ver, s.vrfSk)
	nextEpoch := uint64(len(s.histInfo))
	val, open := genValComm(nextEpoch, pk)
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

// Get rets, among others, whether the uid has been registered,
// and if so, a complete latest memb proof.
func (s *Server) Get(uid uint64) (*SigDig, []*MembHide, bool, *Memb, *NonMemb) {
	s.mu.Lock()
	dig := s.getDig()
	hist := s.getHist(uid)
	bound := s.getBound(uid)
	nextVer := s.nextVers[uid]
	if nextVer == 0 {
		s.mu.Unlock()
		return dig, hist, false, &Memb{CommOpen: &PkCommOpen{}}, bound
	}
	latest := s.getLatest(uid)
	s.mu.Unlock()
	return dig, hist, true, latest, bound
}

func (s *Server) SelfMon(uid uint64) (*SigDig, *NonMemb) {
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
		return &UpdateProof{Updates: make(map[string][]byte)}, true
	}
	info := s.histInfo[epoch]
	s.mu.Unlock()
	p := &UpdateProof{Updates: info.updates, Sig: info.sig}
	return p, false
}

func NewServer() (*Server, cryptoffi.SigPublicKey, *cryptoffi.VrfPublicKey) {
	mu := new(sync.Mutex)
	sigPk, sigSk := cryptoffi.SigGenerateKey()
	vrfPk, vrfSk := cryptoffi.VrfGenerateKey()
	m := &merkle.Tree{}
	opens := make(map[string]*PkCommOpen)
	vers := make(map[uint64]uint64)

	// commit to init epoch.
	dig := m.Digest()
	updates := make(map[string][]byte)
	// TODO: maybe factor this out along with Put code.
	preSig := &PreSigDig{Epoch: 0, Dig: dig}
	preSigByt := PreSigDigEncode(make([]byte, 0), preSig)
	sig := sigSk.Sign(preSigByt)
	newInfo := &servEpochInfo{updates: updates, dig: dig, sig: sig}
	var hist []*servEpochInfo
	hist = append(hist, newInfo)
	return &Server{mu: mu, sigSk: sigSk, vrfSk: vrfSk, keyMap: m, histInfo: hist, pkCommOpens: opens, nextVers: vers}, sigPk, vrfPk
}
