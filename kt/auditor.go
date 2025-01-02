package kt

import (
	"github.com/goose-lang/primitive"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/merkle"
	"sync"
)

type Auditor struct {
	mu       *sync.Mutex
	sk       *cryptoffi.SigPrivateKey
	keyMap   *merkle.Tree
	histInfo []*AdtrEpochInfo
}

// Update checks new epoch updates, applies them, and errors on fail.
func (a *Auditor) Update(proof *UpdateProof) bool {
	a.mu.Lock()
	nextEp := uint64(len(a.histInfo))
	if checkUpd(a.keyMap, nextEp, proof.Updates) {
		a.mu.Unlock()
		return true
	}
	applyUpd(a.keyMap, proof.Updates)

	// sign dig.
	dig := a.keyMap.Digest()
	preSig := &PreSigDig{Epoch: nextEp, Dig: dig}
	preSigByt := PreSigDigEncode(make([]byte, 0), preSig)
	sig := a.sk.Sign(preSigByt)
	newInfo := &AdtrEpochInfo{Dig: dig, ServSig: proof.Sig, AdtrSig: sig}
	a.histInfo = append(a.histInfo, newInfo)
	a.mu.Unlock()
	return false
}

// Get returns the auditor's dig for a particular epoch, and errors on fail.
func (a *Auditor) Get(epoch uint64) (*AdtrEpochInfo, bool) {
	a.mu.Lock()
	numEpochs := uint64(len(a.histInfo))
	if epoch >= numEpochs {
		a.mu.Unlock()
		return &AdtrEpochInfo{}, true
	}

	info := a.histInfo[epoch]
	a.mu.Unlock()
	return info, false
}

func NewAuditor() (*Auditor, cryptoffi.SigPublicKey) {
	mu := new(sync.Mutex)
	pk, sk := cryptoffi.SigGenerateKey()
	m := merkle.NewTree()
	return &Auditor{mu: mu, sk: sk, keyMap: m}, pk
}

// checkUpd checks that updates are okay to apply, and errors on fail.
func checkUpd(keys *merkle.Tree, nextEp uint64, upd map[string][]byte) bool {
	var loopErr bool
	for mapLabel, mapVal := range upd {
		_, _, proofTy, _, err0 := keys.Get([]byte(mapLabel))
		// label has right len. used in applyUpd.
		if err0 {
			loopErr = true
		}
		// label not already in keyMap. map monotonicity.
		if proofTy {
			loopErr = true
		}
		valPre, rem, err1 := MapValPreDecode(mapVal)
		// val bytes exactly encode MapVal.
		// could relax to at least encode epoch, but this is logically
		// more straightforward to deal with.
		if err1 || len(rem) != 0 {
			loopErr = true
		}
		// epoch ok.
		if valPre.Epoch != nextEp {
			loopErr = true
		}
	}
	return loopErr
}

// applyUpd applies a valid update.
func applyUpd(keys *merkle.Tree, upd map[string][]byte) {
	for label, val := range upd {
		_, _, err0 := keys.Put([]byte(label), val)
		primitive.Assert(!err0)
	}
}
