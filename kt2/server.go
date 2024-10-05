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

func (s *Server) getMembProof(uid, ver uint64) *MembProof {
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

func (s *Server) getHistProof(uid uint64) *HistProof {
	// get signed dig.
	numEpochs := uint64(len(s.histInfo))
	lastInfo := s.histInfo[numEpochs-1]
	sigDig := &SigDig{Epoch: numEpochs - 1, Dig: lastInfo.dig, Sig: lastInfo.sig}

	// get memb proofs for all existing versions.
	var membs []*MembProof
	nextVer := s.nextVers[uid]
	for ver := uint64(0); ver < nextVer; ver++ {
		membs = append(membs, s.getMembProof(uid, ver))
	}

	// get non-memb proof for next version.
	nextLabel, nextVrfProof := compMapLabel(uid, nextVer, s.vrfSk)
	nextReply := s.keyMap.Get(nextLabel)
	primitive.Assert(!nextReply.Error)
	primitive.Assert(!nextReply.ProofTy)
	nonMemb := &NonMembProof{Label: nextLabel, VrfProof: nextVrfProof, MerkProof: nextReply.Proof}

	return &HistProof{SigDig: sigDig, Membs: membs, NonMemb: nonMemb}
}

func (s *Server) Put(uid uint64, pk []byte) *HistProof {
	s.mu.Lock()
	// add to keyMap.
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

	// get history proof.
	histProof := s.getHistProof(uid)
	s.mu.Unlock()
	return histProof
}

func (s *Server) Get(uid uint64) *HistProof {
	s.mu.Lock()
	p := s.getHistProof(uid)
	s.mu.Unlock()
	return p
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
