package kt

import (
	"github.com/goose-lang/std"
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
	if checkUpd(a.keyMap, proof.Updates) {
		a.mu.Unlock()
		return true
	}
	applyUpd(a.keyMap, proof.Updates)

	dig := a.keyMap.Digest()
	// sign dig.
	preSig := &PreSigDig{Epoch: nextEp, Dig: dig}
	preSigByt := PreSigDigEncode(make([]byte, 0, 8+8+cryptoffi.HashLen), preSig)
	sig := a.sk.Sign(preSigByt)
	// benchmark: turn off sigs for akd compat.
	// var sig []byte

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

func checkUpd(keys *merkle.Tree, upd map[string][]byte) bool {
	var loopErr bool
	for mapLabel := range upd {
		if checkOneUpd(keys, []byte(mapLabel)) {
			loopErr = true
		}
	}
	return loopErr
}

// checkOneUpd checks that an update is safe to apply, and errs on fail.
func checkOneUpd(keys *merkle.Tree, mapLabel []byte) bool {
	// used in applyUpd.
	if uint64(len(mapLabel)) != cryptoffi.HashLen {
		return true
	}
	inTree, _ := keys.Get(mapLabel)
	// label not already in keyMap. map monotonicity.
	if inTree {
		return true
	}
	return false
}

// applyUpd applies a valid update to the previous map.
func applyUpd(keys *merkle.Tree, upd map[string][]byte) {
	for label, val := range upd {
		err0 := keys.Put([]byte(label), val)
		std.Assert(!err0)
	}
}
