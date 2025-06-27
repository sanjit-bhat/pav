package auditor

import (
	"sync"

	"github.com/goose-lang/std"
	"github.com/sanjit-bhat/pav/advrpc"
	"github.com/sanjit-bhat/pav/cryptoffi"
	"github.com/sanjit-bhat/pav/hashchain"
	"github.com/sanjit-bhat/pav/ktcore"
	"github.com/sanjit-bhat/pav/merkle"
	"github.com/sanjit-bhat/pav/server"
)

type Auditor struct {
	mu      *sync.RWMutex
	sk      *cryptoffi.SigPrivateKey
	lastDig []byte
	hist    []*history
	serv    *serv
}

type history struct {
	link    []byte
	servSig []byte
	adtrSig []byte
}

type serv struct {
	cli        *advrpc.Client
	sigPk      cryptoffi.SigPublicKey
	vrfPk      []byte
	servVrfSig []byte
	adtrVrfSig []byte
}

// Update queries server for a new epoch update, applies it, and errors on fail.
func (a *Auditor) Update() ktcore.Blame {
	a.mu.Lock()
	numEps := uint64(len(a.hist))
	upd, err0 := server.CallAudit(a.serv.cli, numEps)
	if err0 != ktcore.BlameNone {
		a.mu.Unlock()
		return err0
	}

	var err1 ktcore.Blame
	for _, p := range upd {
		err2 := a.updOnce(p)
		if err2 != ktcore.BlameNone {
			err1 = err2
		}
	}
	a.mu.Unlock()
	return err1
}

func (a *Auditor) updOnce(p *ktcore.AuditProof) ktcore.Blame {
	numEps := uint64(len(a.hist))
	var lastLink []byte
	if numEps == 0 {
		// start off with empty chain.
		lastLink = hashchain.GetEmptyLink()
	} else {
		lastLink = a.hist[numEps-1].link
	}

	// check update.
	nextDig, err0 := getNextDig(a.lastDig, p.Updates)
	if err0 {
		return ktcore.BlameServFull
	}
	nextLink := hashchain.GetNextLink(lastLink, nextDig)
	if ktcore.VerifyLinkSig(a.serv.sigPk, numEps, nextLink, p.LinkSig) {
		return ktcore.BlameServFull
	}

	// sign and apply update.
	sig := ktcore.SignLink(a.sk, numEps, nextLink)
	a.lastDig = nextDig
	info := &history{link: nextLink, servSig: p.LinkSig, adtrSig: sig}
	a.hist = append(a.hist, info)
	return ktcore.BlameNone
}

// Get returns the auditor's info for a particular epoch, and errors on fail.
func (a *Auditor) Get(epoch uint64) *GetReply {
	a.mu.RLock()
	numEpochs := uint64(len(a.hist))
	if epoch >= numEpochs {
		a.mu.RUnlock()
		// could legitimately get bad epoch if we're lagging behind.
		return &GetReply{Err: ktcore.BlameUnknown}
	}

	x := a.hist[epoch]
	a.mu.RUnlock()
	return &GetReply{Link: x.link, ServLinkSig: x.servSig, AdtrLinkSig: x.adtrSig, VrfPk: a.serv.vrfPk, ServVrfSig: a.serv.servVrfSig, AdtrVrfSig: a.serv.adtrVrfSig}
}

func New(servAddr uint64, servPk cryptoffi.SigPublicKey) (*Auditor, cryptoffi.SigPublicKey, ktcore.Blame) {
	cli := advrpc.Dial(servAddr)
	reply, err0 := server.CallStart(cli)
	if err0 != ktcore.BlameNone {
		return nil, nil, err0
	}
	if ktcore.VerifyVrfSig(servPk, reply.VrfPk, reply.VrfSig) {
		return nil, nil, ktcore.BlameServFull
	}

	mu := new(sync.RWMutex)
	pk, sk := cryptoffi.SigGenerateKey()
	// start off with dig of empty map.
	tr := merkle.New()
	dig := tr.Digest()
	sig := ktcore.SignVrf(sk, reply.VrfPk)
	serv := &serv{cli: cli, sigPk: servPk, vrfPk: reply.VrfPk, servVrfSig: reply.VrfSig, adtrVrfSig: sig}
	return &Auditor{mu: mu, sk: sk, lastDig: dig, serv: serv}, pk, ktcore.BlameNone
}

func getNextDig(lastDig []byte, updates []*ktcore.UpdateProof) ([]byte, bool) {
	var lastDig0 = lastDig
	var err bool
	for _, u := range updates {
		prev, next, err0 := merkle.VerifyUpdate(u.MapLabel, u.MapVal, u.NonMembProof)
		if err0 || !std.BytesEqual(lastDig0, prev) {
			err = true
		}
		lastDig0 = next
	}
	return lastDig0, err
}
