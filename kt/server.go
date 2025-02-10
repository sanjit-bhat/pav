package kt

import (
	"github.com/goose-lang/primitive"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/cryptoutil"
	"github.com/mit-pdos/pav/merkle"
	"log"
	"sync"
)

type Server struct {
	mu    *sync.Mutex
	sigSk *cryptoffi.SigPrivateKey
	vrfSk *cryptoffi.VrfPrivateKey
	// commitSecret is the 32-byte secret used to generate commitments.
	commitSecret []byte
	// keyMap stores (mapLabel, mapVal) entries.
	keyMap *merkle.Tree
	// visibleKeys stores the latest pk (in the clear) associated with
	// a particular uid. keyMap only has commitments of these pk's.
	visibleKeys map[uint64][]byte
	// uidVerRepo provides the authoritative view on the number of versions
	// registered per uid. this corresponds to entries in keyMap.
	// uid is map idx, and # reg versions is len(sl)-1,
	// except when len(sl) == 0, in which case it's 0 versions.
	// it also caches the expensive vrf computations
	// to make a label from a uid and version.
	uidVerRepo map[uint64][]*vrfCache
	// epochHist stores info about prior epochs.
	epochHist []*servEpochInfo
}

type servEpochInfo struct {
	// updates stores (mapLabel, mapVal) keyMap updates.
	updates map[string][]byte
	dig     []byte
	sig     []byte
}

type vrfCache struct {
	// label is the vrf hash.
	label []byte
	proof []byte
}

func (s *Server) Put(uid uint64, pk []byte) (*SigDig, *Memb, *NonMemb) {
	s.mu.Lock()
	upd := make(map[string][]byte)
	l, v := s.addEntry(uid, pk)
	upd[string(l)] = v
	updEpochHist(&s.epochHist, upd, s.keyMap.Digest(), s.sigSk)

	dig := getDig(s.epochHist)
	labels := getLabels(s.uidVerRepo, uid, s.vrfSk)
	isReg, latest := getLatestVer(s.keyMap, labels, s.commitSecret, s.visibleKeys[uid])
	primitive.Assert(isReg)
	bound := getBoundVer(s.keyMap, labels)
	s.mu.Unlock()
	return dig, latest, bound
}

func (s *Server) PutBatch(uidPks map[uint64][]byte, getProofs bool) map[uint64]*ServerPutReply {
	s.mu.Lock()
	upd := make(map[string][]byte, len(uidPks))
	i := 0
	for uid, pk := range uidPks {
		l, v := s.addEntry(uid, pk)
		upd[string(l)] = v
		if i%1_000 == 0 {
			log.Println(i)
		}
		i++
	}
	updEpochHist(&s.epochHist, upd, s.keyMap.Digest(), s.sigSk)

	proofs := make(map[uint64]*ServerPutReply, len(uidPks))
	if getProofs {
		for uid := range uidPks {
			dig := getDig(s.epochHist)
			labels := getLabels(s.uidVerRepo, uid, s.vrfSk)
			isReg, latest := getLatestVer(s.keyMap, labels, s.commitSecret, s.visibleKeys[uid])
			primitive.Assert(isReg)
			bound := getBoundVer(s.keyMap, labels)
			proofs[uid] = &ServerPutReply{
				Dig:    dig,
				Latest: latest,
				Bound:  bound,
			}
		}
	}
	s.mu.Unlock()
	return proofs
}

// addEntry returns the new mapLabel and mapVal.
func (s *Server) addEntry(uid uint64, pk []byte) ([]byte, []byte) {
	// get lat label and make bound label.
	labels := getLabels(s.uidVerRepo, uid, s.vrfSk)
	boundVer := uint64(len(labels))
	latLabel := labels[boundVer-1]
	boundLabel, boundLabelProof := compMapLabel(uid, boundVer, s.vrfSk)
	s.uidVerRepo[uid] = append(labels, &vrfCache{label: boundLabel, proof: boundLabelProof})

	// make mapVal.
	nextEpoch := uint64(len(s.epochHist))
	r := compCommitOpen(s.commitSecret, latLabel.label)
	open := &CommitOpen{Val: pk, Rand: r}
	mapVal := compMapVal(nextEpoch, open)

	// update key map and visible map.
	err1 := s.keyMap.Put(latLabel.label, mapVal)
	primitive.Assert(!err1)
	s.visibleKeys[uid] = pk
	return latLabel.label, mapVal
}

// Get returns a complete history proof for uid.
// if uid is not yet registered, it returns an empty memb proof for
// for the latest version.
func (s *Server) Get(uid uint64) (*SigDig, []*MembHide, bool, *Memb, *NonMemb) {
	s.mu.Lock()
	dig := getDig(s.epochHist)
	labels := getLabels(s.uidVerRepo, uid, s.vrfSk)
	hist := getHistVers(s.keyMap, labels)
	isReg, latest := getLatestVer(s.keyMap, labels, s.commitSecret, s.visibleKeys[uid])
	bound := getBoundVer(s.keyMap, labels)
	s.mu.Unlock()
	return dig, hist, isReg, latest, bound
}

func (s *Server) SelfMon(uid uint64) (*SigDig, *NonMemb) {
	s.mu.Lock()
	dig := getDig(s.epochHist)
	labels := getLabels(s.uidVerRepo, uid, s.vrfSk)
	bound := getBoundVer(s.keyMap, labels)
	s.mu.Unlock()
	return dig, bound
}

// Audit returns an err on fail.
func (s *Server) Audit(epoch uint64) (*UpdateProof, bool) {
	s.mu.Lock()
	if epoch >= uint64(len(s.epochHist)) {
		s.mu.Unlock()
		return &UpdateProof{Updates: make(map[string][]byte)}, true
	}
	info := s.epochHist[epoch]
	s.mu.Unlock()
	return &UpdateProof{Updates: info.updates, Sig: info.sig}, false
}

func NewServer() (*Server, cryptoffi.SigPublicKey, *cryptoffi.VrfPublicKey) {
	mu := new(sync.Mutex)
	sigPk, sigSk := cryptoffi.SigGenerateKey()
	vrfPk, vrfSk := cryptoffi.VrfGenerateKey()
	sec := cryptoffi.RandBytes(cryptoffi.HashLen)
	keys := merkle.NewTree()
	vis := make(map[uint64][]byte)
	var hist []*servEpochInfo
	// commit empty tree as init epoch.
	updEpochHist(&hist, make(map[string][]byte), keys.Digest(), sigSk)
	labels := make(map[uint64][]*vrfCache)
	return &Server{mu: mu, sigSk: sigSk, vrfSk: vrfSk, commitSecret: sec, keyMap: keys, visibleKeys: vis, uidVerRepo: labels, epochHist: hist}, sigPk, vrfPk
}

// compMapLabel rets mapLabel (VRF(uid || ver)) and a VRF proof.
func compMapLabel(uid uint64, ver uint64, sk *cryptoffi.VrfPrivateKey) ([]byte, []byte) {
	l := &MapLabelPre{Uid: uid, Ver: ver}
	lByt := MapLabelPreEncode(make([]byte, 0, 16), l)
	h, p := sk.Hash(lByt)
	return h, p
}

// compMapVal rets mapVal (epoch || Hash(pk || rand)).
func compMapVal(epoch uint64, pkOpen *CommitOpen) []byte {
	openByt := CommitOpenEncode(make([]byte, 0, 8+uint64(len(pkOpen.Val))+8+cryptoffi.HashLen), pkOpen)
	commit := cryptoutil.Hash(openByt)
	v := &MapValPre{Epoch: epoch, PkCommit: commit}
	return MapValPreEncode(make([]byte, 0, 8+8+cryptoffi.HashLen), v)
}

func compCommitOpen(secret, label []byte) []byte {
	var b = make([]byte, 0, 2*cryptoffi.HashLen)
	b = append(b, secret...)
	b = append(b, label...)
	return cryptoutil.Hash(b)
}

// updEpochHist does a signed history update with some new entries.
func updEpochHist(hist *[]*servEpochInfo, upd map[string][]byte, dig []byte, sk *cryptoffi.SigPrivateKey) {
	// epoch := uint64(len(*hist))
	// preSig := &PreSigDig{Epoch: epoch, Dig: dig}
	// preSigByt := PreSigDigEncode(make([]byte, 0, 8+8+cryptoffi.HashLen), preSig)
	// sig := sk.Sign(preSigByt)
	// benchmark: turn off sigs for akd compat.
	var sig []byte
	newInfo := &servEpochInfo{updates: upd, dig: dig, sig: sig}
	*hist = append(*hist, newInfo)
}

// getLabels gets labels for all existing registered versions of a uid
// and a bound version. it doesn't mutate the provided repo.
func getLabels(uidVerRepo map[uint64][]*vrfCache, uid uint64, sk *cryptoffi.VrfPrivateKey) []*vrfCache {
	labels, ok := uidVerRepo[uid]
	if ok {
		primitive.Assert(len(labels) >= 1)
		return labels
	} else {
		label, proof := compMapLabel(uid, 0, sk)
		return []*vrfCache{{label: label, proof: proof}}
	}
}

func getDig(hist []*servEpochInfo) *SigDig {
	numEpochs := uint64(len(hist))
	lastInfo := hist[numEpochs-1]
	return &SigDig{Epoch: numEpochs - 1, Dig: lastInfo.dig, Sig: lastInfo.sig}
}

// getHistVers returns membership proofs for the history of versions
// up until the latest.
func getHistVers(keyMap *merkle.Tree, labels []*vrfCache) []*MembHide {
	numRegVers := uint64(len(labels)) - 1
	if numRegVers == 0 {
		return nil
	}
	// latest registered ver not included in hist.
	var hist = make([]*MembHide, 0, numRegVers-1)
	for ver := uint64(0); ver < numRegVers-1; ver++ {
		label := labels[ver]
		inTree, mapVal, proof, err0 := keyMap.Prove(label.label)
		primitive.Assert(!err0)
		primitive.Assert(inTree)
		hist = append(hist, &MembHide{LabelProof: label.proof, MapVal: mapVal, MerkleProof: proof})
	}
	return hist
}

// getLatestVer returns whether a version is registered, and if so,
// a membership proof for the latest version.
func getLatestVer(keyMap *merkle.Tree, labels []*vrfCache, commitSecret, pk []byte) (bool, *Memb) {
	numRegVers := uint64(len(labels)) - 1
	if numRegVers == 0 {
		return false, &Memb{PkOpen: &CommitOpen{}}
	}
	label := labels[numRegVers-1]
	inTree, mapVal, proof, err0 := keyMap.Prove(label.label)
	primitive.Assert(!err0)
	primitive.Assert(inTree)
	valPre, _, err1 := MapValPreDecode(mapVal)
	primitive.Assert(!err1)
	r := compCommitOpen(commitSecret, label.label)
	open := &CommitOpen{Val: pk, Rand: r}
	return true, &Memb{LabelProof: label.proof, EpochAdded: valPre.Epoch, PkOpen: open, MerkleProof: proof}
}

// getBoundVer returns a non-membership proof for the boundary version.
func getBoundVer(keyMap *merkle.Tree, labels []*vrfCache) *NonMemb {
	boundVer := uint64(len(labels)) - 1
	label := labels[boundVer]
	inTree, _, proof, err0 := keyMap.Prove(label.label)
	primitive.Assert(!err0)
	primitive.Assert(!inTree)
	return &NonMemb{LabelProof: label.proof, MerkleProof: proof}
}

