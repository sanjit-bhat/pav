package auditor

import (
	"bytes"
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
	mu   *sync.RWMutex
	sk   *cryptoffi.SigPrivateKey
	hist *history
	serv *serv
}

type history struct {
	lastDig []byte
	// the epoch of our first hist entry.
	startEp uint64
	// epochs that the server checked Update proofs for.
	// invariant: epochs within bounds.
	// invariant: at least one entry.
	epochs []*epoch
}

type epoch struct {
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
	prevEp := a.hist.startEp + uint64(len(a.hist.epochs)) - 1
	upd, err := server.CallAudit(a.serv.cli, prevEp)
	if err != ktcore.BlameNone {
		return
	}

	for _, p := range upd {
		if a.updOnce(p) {
			err = ktcore.BlameServFull
			return
		}
	}
	return
}

func (a *Auditor) updOnce(p *ktcore.AuditProof) (err bool) {
	sigPk := a.serv.sigPk
	hist := a.hist
	prevEp := hist.startEp + uint64(len(hist.epochs)) - 1
	prevLink := hist.epochs[len(hist.epochs)-1].link
	ep, dig, link, err := getNextLink(sigPk, prevEp, hist.lastDig, prevLink, p)
	if err {
		return
	}

	// counter-sign and apply update.
	sig := ktcore.SignLink(a.sk, ep, link)
	hist.lastDig = dig
	info := &epoch{link: link, servSig: p.LinkSig, adtrSig: sig}
	hist.epochs = append(hist.epochs, info)
	a.hist = hist
	return
}

// Get returns the auditor's info for a particular epoch.
// it errors if the epoch is out of bounds.
func (a *Auditor) Get(epoch uint64) (link *SignedLink, vrf *SignedVrf, err bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	hist := a.hist
	if epoch < hist.startEp {
		// could legitimately get small epoch if we started late.
		err = true
		return
	}
	lastEp := hist.startEp + uint64(len(hist.epochs)) - 1
	if epoch > lastEp {
		// could legitimately get big epoch if we're lagging behind.
		err = true
		return
	}

	x := hist.epochs[epoch-hist.startEp]
	link = &SignedLink{Link: x.link, ServSig: x.servSig, AdtrSig: x.adtrSig}
	vrf = &SignedVrf{VrfPk: a.serv.vrfPk, ServSig: a.serv.servVrfSig, AdtrSig: a.serv.adtrVrfSig}
	return
}

func New(servAddr uint64, servPk cryptoffi.SigPublicKey) (a *Auditor, sigPk cryptoffi.SigPublicKey, err ktcore.Blame) {
	cli := advrpc.Dial(servAddr)
	chain, vrf, err := server.CallStart(cli)
	if err != ktcore.BlameNone {
		return
	}
	startEp, startDig, startLink, errb := CheckStartChain(servPk, chain)
	if errb {
		err = ktcore.BlameServFull
		return
	}
	_, errb = CheckStartVrf(servPk, vrf)
	if errb {
		err = ktcore.BlameServFull
		return
	}

	mu := new(sync.RWMutex)
	sigPk, sk := cryptoffi.SigGenerateKey()
	linkSig := ktcore.SignLink(sk, startEp, startLink)
	info := &epoch{link: startLink, servSig: chain.LinkSig, adtrSig: linkSig}
	hist := &history{lastDig: startDig, startEp: startEp, epochs: []*epoch{info}}
	vrfSig := ktcore.SignVrf(sk, vrf.VrfPk)
	serv := &serv{cli: cli, sigPk: servPk, vrfPk: vrf.VrfPk, servVrfSig: vrf.VrfSig, adtrVrfSig: vrfSig}
	a = &Auditor{mu: mu, sk: sk, hist: hist, serv: serv}
	return
}

func getNextLink(sigPk cryptoffi.SigPublicKey, prevEp uint64, prevDig, prevLink []byte, p *ktcore.AuditProof) (ep uint64, dig, link []byte, err bool) {
	if !std.SumNoOverflow(prevEp, 1) {
		err = true
		return
	}
	ep = prevEp + 1
	if dig, err = getNextDig(prevDig, p.Updates); err {
		return
	}
	link = hashchain.GetNextLink(prevLink, dig)
	if ktcore.VerifyLinkSig(sigPk, ep, link, p.LinkSig) {
		err = true
		return
	}
	return
}

func getNextDig(prevDig []byte, updates []*ktcore.UpdateProof) (dig []byte, err bool) {
	dig = prevDig
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

func CheckStartChain(servPk cryptoffi.SigPublicKey, chain *server.StartChain) (ep uint64, dig, link []byte, err bool) {
	if uint64(len(chain.PrevLink)) != cryptoffi.HashLen {
		err = true
		return
	}
	extLen, dig, link, errb := hashchain.Verify(chain.PrevLink, chain.ChainProof)
	if errb {
		err = true
		return
	}
	// want a starting dig.
	if extLen == 0 {
		err = true
		return
	}
	if !std.SumNoOverflow(chain.PrevEpochLen, extLen-1) {
		err = true
		return
	}
	ep = chain.PrevEpochLen + extLen - 1
	if ktcore.VerifyLinkSig(servPk, ep, link, chain.LinkSig) {
		err = true
		return
	}
	return
}

func CheckStartVrf(servPk cryptoffi.SigPublicKey, vrf *server.StartVrf) (vrfPk *cryptoffi.VrfPublicKey, err bool) {
	vrfPk, errb := cryptoffi.VrfPublicKeyDecode(vrf.VrfPk)
	if errb {
		err = true
		return
	}
	if ktcore.VerifyVrfSig(servPk, vrf.VrfPk, vrf.VrfSig) {
		err = true
		return
	}
	return
}
