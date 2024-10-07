package kt2

import (
	"github.com/goose-lang/primitive"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/merkle"
	"sync"
)

type Auditor struct {
	mu        *sync.Mutex
	sk        cryptoffi.PrivateKey
	servSigPk cryptoffi.PublicKey
	keyMap    *merkle.Tree
	histInfo  []*AdtrEpochInfo
}

// checkUpd checks that updates are okay to apply, and errors on fail.
func (a *Auditor) checkUpd(upd map[string][]byte) bool {
	nextEpoch := uint64(len(a.histInfo))
	var err0 bool
	for mapLabel, mapVal := range upd {
		getReply := a.keyMap.Get([]byte(mapLabel))
		if getReply.Error || getReply.ProofTy {
			err0 = true
			break
		}
		// as long as we store the entire mapVal, don't think it matters
		// if it has more bytes past the MapValPre.
		valPre, _, err1 := MapValPreDecode(mapVal)
		if err1 || valPre.Epoch != nextEpoch {
			err0 = true
			break
		}
	}
	return err0
}

// applyUpd applies updates.
func (a *Auditor) applyUpd(upd map[string][]byte) {
	for label, val := range upd {
		_, _, err0 := a.keyMap.Put([]byte(label), val)
		primitive.Assert(!err0)
	}
}

// Update checks new epoch updates, applies them, and rets err on fail.
func (a *Auditor) Update(proof *UpdateProof) bool {
	a.mu.Lock()
	nextEpoch := uint64(len(a.histInfo))
	if a.checkUpd(proof.Updates) {
		a.mu.Unlock()
		return true
	}
	a.applyUpd(proof.Updates)

	// check dig sig.
	dig := a.keyMap.Digest()
	preSig := &PreSigDig{Epoch: nextEpoch, Dig: dig}
	preSigByt := PreSigDigEncode(make([]byte, 0), preSig)
	ok0 := a.servSigPk.Verify(preSigByt, proof.Sig)
	if !ok0 {
		a.mu.Unlock()
		return true
	}

	// sign dig.
	sig := a.sk.Sign(preSigByt)
	newInfo := &AdtrEpochInfo{Dig: dig, ServSig: proof.Sig, AdtrSig: sig}
	a.histInfo = append(a.histInfo, newInfo)
	a.mu.Unlock()
	return false
}

// Get returns the auditor's known link for a particular epoch,
// and errs on fail.
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

func newAuditor(servPk cryptoffi.PublicKey) (*Auditor, cryptoffi.PublicKey) {
	mu := new(sync.Mutex)
	pk, sk := cryptoffi.GenerateKey()
	m := &merkle.Tree{}
	return &Auditor{mu: mu, sk: sk, servSigPk: servPk, keyMap: m}, pk
}
