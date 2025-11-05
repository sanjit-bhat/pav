package auditor

import (
	"bytes"
	"sync"

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
	// the epoch of the first elem in hist.
	bootEp uint64
	// hist epochs that the server checked Update proofs for.
	hist []*history
	serv *serv
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

// Update queries server for a new epoch update and applies it.
func (a *Auditor) Update() (err ktcore.Blame) {
	a.mu.Lock()
	defer a.mu.Unlock()
	numEps := a.bootEp + uint64(len(a.hist))
	upd, err := server.CallAudit(a.serv.cli, numEps)
	if err != ktcore.BlameNone {
		return
	}

	for _, p := range upd {
		err = a.updOnce(p)
		if err != ktcore.BlameNone {
			return
		}
	}
	return
}

func (a *Auditor) updOnce(p *ktcore.AuditProof) (err ktcore.Blame) {
	nextEp := a.bootEp + uint64(len(a.hist))
	lastLink := a.hist[len(a.hist)-1].link

	// check update.
	nextDig, errb := getNextDig(a.lastDig, p.Updates)
	if errb {
		return ktcore.BlameServFull
	}
	nextLink := hashchain.GetNextLink(lastLink, nextDig)
	if ktcore.VerifyLinkSig(a.serv.sigPk, nextEp, nextLink, p.LinkSig) {
		return ktcore.BlameServFull
	}

	// sign and apply update.
	sig := ktcore.SignLink(a.sk, nextEp, nextLink)
	a.lastDig = nextDig
	info := &history{link: nextLink, servSig: p.LinkSig, adtrSig: sig}
	a.hist = append(a.hist, info)
	return ktcore.BlameNone
}

// Get returns the auditor's info for a particular epoch.
// it errors if the epoch is out of bounds.
func (a *Auditor) Get(epoch uint64) *GetReply {
	a.mu.RLock()
	defer a.mu.RUnlock()
	numEpochs := a.bootEp + uint64(len(a.hist))
	if epoch < a.bootEp {
		// could legitimately get small epoch if we started late.
		return &GetReply{Err: ktcore.BlameUnknown}
	}
	if epoch >= numEpochs {
		// could legitimately get big epoch if we're lagging behind.
		return &GetReply{Err: ktcore.BlameUnknown}
	}

	x := a.hist[epoch-a.bootEp]
	return &GetReply{Link: x.link, ServLinkSig: x.servSig, AdtrLinkSig: x.adtrSig, VrfPk: a.serv.vrfPk, ServVrfSig: a.serv.servVrfSig, AdtrVrfSig: a.serv.adtrVrfSig}
}

func New(servAddr uint64, servPk cryptoffi.SigPublicKey) (a *Auditor, sigPk cryptoffi.SigPublicKey, err ktcore.Blame) {
	cli := advrpc.Dial(servAddr)
	reply, err := server.CallStartAdtr(cli)
	if err != ktcore.BlameNone {
		return
	}
	bootEp, newDig, newLink, err := checkStart(servPk, reply)
	if err != ktcore.BlameNone {
		return
	}

	mu := new(sync.RWMutex)
	sigPk, sk := cryptoffi.SigGenerateKey()
	linkSig := ktcore.SignLink(sk, bootEp, newLink)
	h := &history{link: newLink, servSig: reply.LinkSig, adtrSig: linkSig}
	vrfSig := ktcore.SignVrf(sk, reply.VrfPk)
	serv := &serv{cli: cli, sigPk: servPk, vrfPk: reply.VrfPk, servVrfSig: reply.VrfSig, adtrVrfSig: vrfSig}
	a = &Auditor{mu: mu, sk: sk, lastDig: newDig, bootEp: bootEp, hist: []*history{h}, serv: serv}
	return
}

func getNextDig(lastDig []byte, updates []*ktcore.UpdateProof) (dig []byte, err bool) {
	dig = lastDig
	for _, u := range updates {
		var prev, next []byte
		prev, next, err = merkle.VerifyUpdate(u.MapLabel, u.MapVal, u.NonMembProof)
		if err {
			return
		}
		if !bytes.Equal(dig, prev) {
			err = true
			return
		}
		dig = next
	}
	return
}

func checkStart(servPk cryptoffi.SigPublicKey, reply *server.StartAdtrReply) (bootEp uint64, newDig, newLink []byte, err ktcore.Blame) {
	if ktcore.VerifyVrfSig(servPk, reply.VrfPk, reply.VrfSig) {
		err = ktcore.BlameServFull
		return
	}
	extLen, newDig, newLink, errb := hashchain.Verify(hashchain.GetEmptyLink(), reply.ChainProof)
	if errb {
		err = ktcore.BlameServFull
		return
	}
	// want starting dig.
	if extLen == 0 {
		err = ktcore.BlameServFull
		return
	}
	bootEp = extLen - 1
	if ktcore.VerifyLinkSig(servPk, bootEp, newLink, reply.LinkSig) {
		err = ktcore.BlameServFull
		return
	}
	return
}
