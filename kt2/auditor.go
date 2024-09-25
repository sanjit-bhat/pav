package kt2

import (
	"errors"
	"github.com/goose-lang/primitive"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/merkle"
	"github.com/mit-pdos/pav/rpcffi"
	"sync"
)

type adtrEpochInfo struct {
	dig     []byte
	servSig cryptoffi.Sig
	adtrSig cryptoffi.Sig
}

type Auditor struct {
	mu        *sync.Mutex
	sk        cryptoffi.PrivateKey
	servSigPk cryptoffi.PublicKey
	histInfo  []*adtrEpochInfo
	keyMap    *merkle.Tree
}

// checkUpd checks that updates are safe to apply, and errors on fail.
func (a *Auditor) checkUpd(upd map[string][]byte) bool {
	var err0 bool
	for label := range upd {
		getReply := a.keyMap.Get([]byte(label))
		if getReply.Error || getReply.ProofTy {
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

// Update checks new epoch updates and applies them.
func (a *Auditor) Update(args *UpdateProof, unused *struct{}) error {
	a.mu.Lock()
	nextEpoch := uint64(len(a.histInfo))
	if args.epoch != nextEpoch {
		a.mu.Unlock()
		return errors.New("Auditor.Update")
	}
	if a.checkUpd(args.updates) {
		a.mu.Unlock()
		return errors.New("Auditor.Update")
	}
	a.applyUpd(args.updates)

	// check dig sig.
	dig := a.keyMap.Digest()
	preSig := &PreDigSig{Epoch: nextEpoch, Dig: dig}
	preSigByt := rpcffi.Encode(preSig)
	ok0 := a.servSigPk.Verify(preSigByt, args.sig)
	if !ok0 {
		a.mu.Unlock()
		return errors.New("Auditor.Update")
	}

	// sign dig.
	sig := a.sk.Sign(preSigByt)
	newInfo := &adtrEpochInfo{dig: dig, servSig: args.sig, adtrSig: sig}
	a.histInfo = append(a.histInfo, newInfo)
	a.mu.Unlock()
	return nil
}

// Get returns the auditor's known link for a particular epoch.
func (a *Auditor) Get(epoch *uint64, reply *adtrEpochInfo) error {
	a.mu.Lock()
	numEpochs := uint64(len(a.histInfo))
	if *epoch >= numEpochs {
		a.mu.Unlock()
		return errors.New("Auditor.Get")
	}

	inf := a.histInfo[*epoch]
	*reply = *inf
	a.mu.Unlock()
	return nil
}

func newAuditor(servPk cryptoffi.PublicKey) (*Auditor, cryptoffi.PublicKey) {
	mu := new(sync.Mutex)
	pk, sk := cryptoffi.GenerateKey()
	m := &merkle.Tree{}
	return &Auditor{mu: mu, sk: sk, servSigPk: servPk, keyMap: m}, pk
}
