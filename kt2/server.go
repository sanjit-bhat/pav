package kt2

import (
	"errors"
	"github.com/goose-lang/primitive"
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/merkle"
	"github.com/mit-pdos/pav/rpcffi"
	"sync"
)

type mapLabel struct {
	uid uint64
	ver uint64
}

type servEpochInfo struct {
	// updates stores (string(label), val) keyMap updates.
	updates map[string][]byte
	dig     []byte
	sig     []byte
}

type Server struct {
	mu       *sync.Mutex
	sigSk    cryptoffi.PrivateKey
	vrfSk    *cryptoffi.VRFPrivateKey
	histInfo []*servEpochInfo
	// keyMap stores (VRF(uid, version), Hash(pk)).
	keyMap *merkle.Tree
	// fullKeyMap stores (VRF(uid, version), pk).
	fullKeyMap map[string][]byte
	// uidVer stores (uid, next version #).
	uidVer map[uint64]uint64
}

type PutArgs struct {
	uid uint64
	pk  []byte
}

type histMembProof struct {
	label     []byte
	vrfProof  []byte
	pk        []byte
	merkProof [][][]byte
}

type histNonMembProof struct {
	label     []byte
	vrfProof  []byte
	merkProof [][][]byte
}

type HistProof struct {
	sigDig  *SigDig
	membs   []*histMembProof
	nonMemb *histNonMembProof
}

func compMapLabel(uid uint64, ver uint64, sk *cryptoffi.VRFPrivateKey) ([]byte, []byte) {
	l := &mapLabel{uid: uid, ver: ver}
	lByt := rpcffi.Encode(l)
	h, p := sk.Hash(lByt)
	return h, p
}

func (s *Server) getHistProof(uid uint64) *HistProof {
	// get signed dig.
	numEpochs := uint64(len(s.histInfo))
	lastInfo := s.histInfo[numEpochs-1]
	sigDig := &SigDig{Epoch: numEpochs - 1, Dig: lastInfo.dig, Sig: lastInfo.sig}

	// get memb proofs for all existing versions.
	var membs []*histMembProof
	nextVer := s.uidVer[uid]
	for ver := uint64(0); ver < nextVer; ver++ {
		label, vrfProof := compMapLabel(uid, ver, s.vrfSk)
		getReply := s.keyMap.Get(label)
		primitive.Assert(!getReply.Error)
		primitive.Assert(getReply.ProofTy)
		pk, ok := s.fullKeyMap[string(label)]
		primitive.Assert(ok)
		newMemb := &histMembProof{label: label, vrfProof: vrfProof, pk: pk, merkProof: getReply.Proof}
		membs = append(membs, newMemb)
	}

	// get non-memb proof for next version.
	nextLabel, nextVrfProof := compMapLabel(uid, nextVer, s.vrfSk)
	nextReply := s.keyMap.Get(nextLabel)
	primitive.Assert(!nextReply.Error)
	primitive.Assert(!nextReply.ProofTy)
	nonMemb := &histNonMembProof{label: nextLabel, vrfProof: nextVrfProof, merkProof: nextReply.Proof}

	return &HistProof{sigDig: sigDig, membs: membs, nonMemb: nonMemb}
}

func (s *Server) Put(args *PutArgs, reply *HistProof) error {
	s.mu.Lock()
	// add to keyMap.
	ver, _ := s.uidVer[args.uid]
	label, _ := compMapLabel(args.uid, ver, s.vrfSk)
	val := cryptoffi.Hash(args.pk)
	dig, _, err0 := s.keyMap.Put(label, val)
	primitive.Assert(!err0)

	// update supporting stores.
	// assume that we'll run out of mem before running out of versions.
	s.uidVer[args.uid] = std.SumAssumeNoOverflow(ver, 1)
	s.fullKeyMap[string(label)] = args.pk

	// sign new dig.
	updates := map[string][]byte{
		string(label): val,
	}
	nextEpoch := uint64(len(s.histInfo))
	preSig := &PreDigSig{Epoch: nextEpoch, Dig: dig}
	sig := s.sigSk.Sign(rpcffi.Encode(preSig))
	newInfo := &servEpochInfo{updates: updates, dig: dig, sig: sig}
	s.histInfo = append(s.histInfo, newInfo)

	// get history proof.
	*reply = *s.getHistProof(args.uid)
	s.mu.Unlock()
	return nil
}

func (s *Server) Get(uid *uint64, reply *HistProof) error {
	s.mu.Lock()
	*reply = *s.getHistProof(*uid)
	s.mu.Unlock()
	return nil
}

type UpdateProof struct {
	epoch   uint64
	updates map[string][]byte
	sig     []byte
}

func (s *Server) Audit(epoch *uint64, reply *UpdateProof) error {
	s.mu.Lock()
	if *epoch >= uint64(len(s.histInfo)) {
		s.mu.Unlock()
		return errors.New("Audit")
	}
	inf := s.histInfo[*epoch]
	reply.updates = inf.updates
	reply.sig = inf.sig
	s.mu.Unlock()
	return nil
}

func newServer() (*Server, cryptoffi.PublicKey, *cryptoffi.VRFPublicKey) {
	mu := new(sync.Mutex)
	sigPk, sigSk := cryptoffi.GenerateKey()
	vrfPk, vrfSk := cryptoffi.VRFGenerateKey()
	m := &merkle.Tree{}
	fullM := make(map[string][]byte)
	verM := make(map[uint64]uint64)
	return &Server{mu: mu, sigSk: sigSk, vrfSk: vrfSk, keyMap: m, fullKeyMap: fullM, uidVer: verM}, sigPk, vrfPk
}
