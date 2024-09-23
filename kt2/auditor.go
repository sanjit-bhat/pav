package kt2

import (
	"errors"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/merkle"
	"sync"
)

type adtrEpochInfo struct {
	prevLink []byte
	dig      []byte
	link     []byte
	servSig  cryptoffi.Sig
	adtrSig  cryptoffi.Sig
}

type Auditor struct {
	mu       *sync.Mutex
	sk       cryptoffi.PrivateKey
	servPk   cryptoffi.PublicKey
	keyMap   *merkle.Tree
	sigLinks []*adtrEpochInfo
}

// appOnly checks that updates are append-only, and applies them.
// TODO: for err recovery, should prob check first (both against prev tree
// and against other updates), then apply.
func (a *Auditor) appOnly(upd []*mapEntry) errorTy {
	var err0 errorTy
	for _, e := range upd {
		getReply := a.keyMap.Get(e.labelHash)
		// already in the tree.
		if getReply.Error || getReply.ProofTy {
			err0 = true
			break
		}

		_, _, err1 := a.keyMap.Put(e.labelHash, e.valHash)
		if err1 {
			err0 = true
			break
		}
	}
	if err0 {
		return true
	}
	return false
}

// Update checks new epoch updates and applies them.
func (a *Auditor) Update(args *AuditUpd, unused *struct{}) error {
	a.mu.Lock()
	numEpochs := uint64(len(a.sigLinks))
	if args.epoch != numEpochs {
		a.mu.Unlock()
		return errors.New("Auditor.Update")
	}

	if a.appOnly(args.updates) {
		a.mu.Unlock()
		return errors.New("Auditor.Update")
	}

	// re-compute link and check sig.
	var prevLink []byte
	if numEpochs == 0 {
		prevLink = firstLink()
	} else {
		prevLink = a.sigLinks[numEpochs-1].link
	}
	dig := a.keyMap.Digest()
	link := nextLink(numEpochs, prevLink, dig)
	ok0 := a.servPk.Verify(link, args.linkSig)
	if !ok0 {
		a.mu.Unlock()
		return errors.New("Auditor.Update")
	}

	// sign new link.
	sig := a.sk.Sign(link)
	inf := &adtrEpochInfo{prevLink: prevLink, dig: dig, link: link, servSig: args.linkSig, adtrSig: sig}
	a.sigLinks = append(a.sigLinks, inf)
	a.mu.Unlock()
	return nil
}

// Get returns the auditor's known link for a particular epoch.
func (a *Auditor) Get(epoch *uint64, reply *adtrEpochInfo) error {
	a.mu.Lock()
	numEpochs := uint64(len(a.sigLinks))
	if *epoch >= numEpochs {
		a.mu.Unlock()
		return errors.New("Auditor.Get")
	}

	inf := a.sigLinks[*epoch]
	*reply = *inf
	a.mu.Unlock()
	return nil
}

func newAuditor(servPk cryptoffi.PublicKey) (*Auditor, cryptoffi.PublicKey) {
	mu := new(sync.Mutex)
	pk, sk := cryptoffi.GenerateKey()
	m := &merkle.Tree{}
	return &Auditor{mu: mu, sk: sk, servPk: servPk, keyMap: m}, pk
}
