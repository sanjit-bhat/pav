package auditor

import (
	"sync"

	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/hashchain"
	"github.com/mit-pdos/pav/ktserde"
	"github.com/mit-pdos/pav/merkle"
)

type Auditor struct {
	mu      *sync.RWMutex
	sk      *cryptoffi.SigPrivateKey
	servPk  cryptoffi.SigPublicKey
	lastDig []byte
	hist    []*EpochInfo
}

// Update checks a new epoch update, applies it, and errors on fail.
func (a *Auditor) Update(proof *ktserde.AuditProof) bool {
	a.mu.Lock()
	nextEp := uint64(len(a.hist))
	var lastLink []byte
	if nextEp == 0 {
		// start off with empty chain.
		lastLink = hashchain.GetEmptyLink()
	} else {
		lastLink = a.hist[nextEp-1].Link
	}

	// check update.
	nextDig, err0 := getNextDig(a.lastDig, proof.Updates)
	if err0 {
		a.mu.Unlock()
		return true
	}
	nextLink := hashchain.GetNextLink(lastLink, nextDig)
	preSig := &ktserde.PreSigDig{Epoch: nextEp, Dig: nextLink}
	preSigByt := ktserde.PreSigDigEncode(make([]byte, 0, 8+8+cryptoffi.HashLen), preSig)
	if a.servPk.Verify(preSigByt, proof.LinkSig) {
		a.mu.Unlock()
		return true
	}

	// sign and apply update.
	sig := a.sk.Sign(preSigByt)
	// benchmark: turn off sigs for akd compat.
	// var sig []byte
	a.lastDig = nextDig
	info := &EpochInfo{Link: nextLink, ServSig: proof.LinkSig, AdtrSig: sig}
	a.hist = append(a.hist, info)
	a.mu.Unlock()
	return false
}

// Get returns the auditor's info for a particular epoch, and errors on fail.
func (a *Auditor) Get(epoch uint64) (*EpochInfo, bool) {
	a.mu.RLock()
	numEpochs := uint64(len(a.hist))
	if epoch >= numEpochs {
		a.mu.RUnlock()
		return &EpochInfo{}, true
	}

	info := a.hist[epoch]
	a.mu.RUnlock()
	return info, false
}

func New(servPk cryptoffi.SigPublicKey) (*Auditor, cryptoffi.SigPublicKey) {
	mu := new(sync.RWMutex)
	pk, sk := cryptoffi.SigGenerateKey()
	// start off with dig of empty map.
	tr := merkle.New()
	dig := tr.Digest()
	return &Auditor{mu: mu, sk: sk, servPk: servPk, lastDig: dig}, pk
}

func getNextDig(lastDig []byte, updates []*ktserde.UpdateProof) ([]byte, bool) {
	var lastDig0 = lastDig
	var err bool
	for _, u := range updates {
		prev, next, err0 := merkle.VerifyUpdate(u.MapLabel, u.MapVal, u.NonMembProof)
		if err0 {
			err = true
			break
		}
		if !std.BytesEqual(lastDig0, prev) {
			err = true
			break
		}
		lastDig0 = next
	}
	if err {
		return nil, true
	}
	return lastDig0, false
}
