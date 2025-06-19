package auditor

import (
	"sync"

	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/advrpc"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/hashchain"
	"github.com/mit-pdos/pav/ktcore"
	"github.com/mit-pdos/pav/merkle"
	"github.com/mit-pdos/pav/server"
)

type Auditor struct {
	mu      *sync.RWMutex
	sk      *cryptoffi.SigPrivateKey
	lastDig []byte
	hist    []*epochInfo
	server  *serverInfo
}

type epochInfo struct {
	link    []byte
	servSig []byte
	adtrSig []byte
}

type serverInfo struct {
	cli        *advrpc.Client
	sigPk      cryptoffi.SigPublicKey
	vrfPk      []byte
	servVrfSig []byte
	adtrVrfSig []byte
}

// Update queries server for a new epoch update, applies it, and errors on fail.
func (a *Auditor) Update() bool {
	a.mu.Lock()
	nextEp := uint64(len(a.hist))
	upd, err0 := server.CallAudit(a.server.cli, nextEp)
	if err0 {
		a.mu.Unlock()
		return true
	}

	var lastLink []byte
	if nextEp == 0 {
		// start off with empty chain.
		lastLink = hashchain.GetEmptyLink()
	} else {
		lastLink = a.hist[nextEp-1].link
	}

	// check update.
	nextDig, err1 := getNextDig(a.lastDig, upd.Updates)
	if err1 {
		a.mu.Unlock()
		return true
	}
	nextLink := hashchain.GetNextLink(lastLink, nextDig)
	if ktcore.VerifyLinkSig(a.server.sigPk, nextEp, nextLink, upd.LinkSig) {
		a.mu.Unlock()
		return true
	}

	// sign and apply update.
	sig := ktcore.SignLink(a.sk, nextEp, nextLink)
	a.lastDig = nextDig
	info := &epochInfo{link: nextLink, servSig: upd.LinkSig, adtrSig: sig}
	a.hist = append(a.hist, info)
	a.mu.Unlock()
	return false
}

// Get returns the auditor's info for a particular epoch, and errors on fail.
func (a *Auditor) Get(epoch uint64) *GetReply {
	stdErr := &GetReply{Err: true}
	a.mu.RLock()
	numEpochs := uint64(len(a.hist))
	if epoch >= numEpochs {
		a.mu.RUnlock()
		return stdErr
	}

	x := a.hist[epoch]
	a.mu.RUnlock()
	return &GetReply{Link: x.link, ServLinkSig: x.servSig, AdtrLinkSig: x.adtrSig, VrfPk: a.server.vrfPk, ServVrfSig: a.server.servVrfSig, AdtrVrfSig: a.server.adtrVrfSig}
}

func New(servAddr uint64, servPk cryptoffi.SigPublicKey) (*Auditor, cryptoffi.SigPublicKey, bool) {
	cli := advrpc.Dial(servAddr)
	reply, err0 := server.CallStart(cli)
	if err0 {
		return nil, nil, true
	}
	if ktcore.VerifyVrfSig(servPk, reply.VrfPk, reply.VrfSig) {
		return nil, nil, true
	}

	mu := new(sync.RWMutex)
	pk, sk := cryptoffi.SigGenerateKey()
	// start off with dig of empty map.
	tr := merkle.New()
	dig := tr.Digest()
	sig := ktcore.SignVrf(sk, reply.VrfPk)
	serv := &serverInfo{cli: cli, sigPk: servPk, vrfPk: reply.VrfPk, servVrfSig: reply.VrfSig, adtrVrfSig: sig}
	return &Auditor{mu: mu, sk: sk, lastDig: dig, server: serv}, pk, false
}

func getNextDig(lastDig []byte, updates []*ktcore.UpdateProof) ([]byte, bool) {
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
