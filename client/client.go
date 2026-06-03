package client

import (
	"bytes"

	"github.com/goose-lang/std"
	"github.com/sanjit-bhat/pav/advrpc"
	"github.com/sanjit-bhat/pav/auditor"
	"github.com/sanjit-bhat/pav/cryptoffi"
	"github.com/sanjit-bhat/pav/hashchain"
	"github.com/sanjit-bhat/pav/ktcore"
	"github.com/sanjit-bhat/pav/merkle"
	"github.com/sanjit-bhat/pav/server"
)

type Client struct {
	uid     uint64
	nextVer *ver
	lastEp  *epoch
	serv    *serv
}

type ver struct {
	ver       uint64
	hasPendPk bool
	pendPk    []byte
}

type epoch struct {
	epoch uint64
	dig   []byte
	link  []byte
	sig   []byte
}

type serv struct {
	cli    *advrpc.Client
	sigPk  cryptoffi.SigPublicKey
	vrfPk  *cryptoffi.VrfPublicKey
	vrfSig []byte
}

// Put queues pk for insertion.
// if we have a pending Put, it requires the pk to be the same.
func (c *Client) Put(pk []byte) {
	if c.nextVer.hasPendPk {
		std.Assert(bytes.Equal(c.nextVer.pendPk, pk))
	} else {
		c.nextVer.hasPendPk = true
		c.nextVer.pendPk = pk
	}
	server.CallPut(c.serv.cli, c.uid, pk, c.nextVer.ver)
}

// Get a uid's pk.
func (c *Client) Get(uid uint64) (ep uint64, hasPk bool, pk []byte, err ktcore.Blame) {
	nextEp, pks, err := c.getHistory(uid, 0)
	if err != ktcore.BlameNone {
		return
	}

	c.lastEp = nextEp
	ep = nextEp.epoch
	if len(pks) != 0 {
		hasPk = true
		pk = pks[len(pks)-1]
	}
	return
}

// SelfMon a client's own uid.
// if isChanged, the key was added sometime from the last SelfMon.
func (c *Client) SelfMon() (ep uint64, isChanged bool, err ktcore.Blame) {
	nextEp, pks, err := c.getHistory(c.uid, c.nextVer.ver)
	if err != ktcore.BlameNone {
		return
	}
	ep = nextEp.epoch
	isChanged, errb := checkPend(c.nextVer, pks)
	if errb {
		// conflicting updates could also come from other bad clients.
		err = ktcore.BlameServFull | ktcore.BlameClients
		return
	}

	c.lastEp = nextEp
	if !isChanged {
		return
	}
	c.nextVer.hasPendPk = false
	c.nextVer.pendPk = nil
	c.nextVer.ver++
	return
}

// checkPend validates that pks align with pend.
func checkPend(pend *ver, pks [][]byte) (isChanged, err bool) {
	if len(pks) == 0 {
		return
	}
	isChanged = true
	err = len(pks) > 1 || !pend.hasPendPk || !bytes.Equal(pks[0], pend.pendPk)
	return
}

func (c *Client) Audit(adtrAddr uint64, adtrPk cryptoffi.SigPublicKey) (startEp, ep uint64, err ktcore.Blame, evid *ktcore.Evid) {
	cli := advrpc.Dial(adtrAddr)
	startEp, startLink, currLink, vrf, err := auditor.CallGet(cli, c.lastEp.epoch)
	if err != ktcore.BlameNone {
		return
	}
	// check adtr sig for consistency under untrusted server and trusted auditor.
	// check serv sig to catch serv misbehavior.
	if checkAuditLink(c.serv.sigPk, adtrPk, startEp, startLink) {
		err = ktcore.BlameAdtrFull
		return
	}
	if checkAuditLink(c.serv.sigPk, adtrPk, c.lastEp.epoch, currLink) {
		err = ktcore.BlameAdtrFull
		return
	}
	if checkAuditVrf(c.serv.sigPk, adtrPk, vrf) {
		err = ktcore.BlameAdtrFull
		return
	}

	// vrf evidence.
	vrfPkB := cryptoffi.VrfPublicKeyEncode(c.serv.vrfPk)
	if !bytes.Equal(vrfPkB, vrf.VrfPk) {
		evid = &ktcore.Evid{Vrf: &ktcore.EvidVrf{VrfPk0: vrfPkB, Sig0: c.serv.vrfSig, VrfPk1: vrf.VrfPk, Sig1: vrf.ServSig}}
		err = ktcore.BlameServSig
		return
	}
	// link evidence.
	if !bytes.Equal(c.lastEp.link, currLink.Link) {
		evid = &ktcore.Evid{Link: &ktcore.EvidLink{Epoch: c.lastEp.epoch, Link0: c.lastEp.link, Sig0: c.lastEp.sig, Link1: currLink.Link, Sig1: currLink.ServSig}}
		err = ktcore.BlameServSig
		return
	}
	ep = c.lastEp.epoch
	return
}

func New(uid, servAddr uint64, servPk cryptoffi.SigPublicKey) (c *Client, ep uint64, err ktcore.Blame) {
	cli := advrpc.Dial(servAddr)
	chain, vrf, err := server.CallStart(cli)
	if err != ktcore.BlameNone {
		return
	}
	startEp, startDig, startLink, errb := auditor.CheckStartChain(servPk, chain)
	if errb {
		err = ktcore.BlameServFull
		return
	}
	vrfPk, errb := auditor.CheckStartVrf(servPk, vrf)
	if errb {
		err = ktcore.BlameServFull
		return
	}

	ver := &ver{}
	lastEp0 := &epoch{epoch: startEp, dig: startDig, link: startLink, sig: chain.LinkSig}
	serv := &serv{cli: cli, sigPk: servPk, vrfPk: vrfPk, vrfSig: vrf.VrfSig}
	c = &Client{uid: uid, nextVer: ver, lastEp: lastEp0, serv: serv}

	// certify starting ver = 0.
	lastEp1, pks, err := c.getHistory(c.uid, 0)
	if err != ktcore.BlameNone {
		return
	}
	ep = lastEp1.epoch
	if len(pks) != 0 {
		err = ktcore.BlameServFull | ktcore.BlameClients
		return
	}
	c.lastEp = lastEp1
	return
}

func (c *Client) getHistory(uid uint64, prevVerLen uint64) (nextEp *epoch, pks [][]byte, err ktcore.Blame) {
	chainProof, sig, hist, bound, err := server.CallHistory(c.serv.cli, uid, c.lastEp.epoch, prevVerLen)
	if err != ktcore.BlameNone {
		return
	}
	nextEp, errb := getNextEp(c.lastEp, c.serv.sigPk, chainProof, sig)
	if errb {
		err = ktcore.BlameServFull
		return
	}
	boundVer := prevVerLen + uint64(len(hist))
	if !std.SumNoOverflow(prevVerLen, uint64(len(hist))) {
		err = ktcore.BlameServFull
		return
	}
	if checkMembs(c.serv.vrfPk, uid, prevVerLen, nextEp.dig, hist) {
		err = ktcore.BlameServFull
		return
	}
	if checkNonMemb(c.serv.vrfPk, uid, boundVer, nextEp.dig, bound) {
		err = ktcore.BlameServFull
		return
	}
	pks = make([][]byte, 0, len(hist))
	for _, x := range hist {
		pks = append(pks, x.PkOpen.Val)
	}
	return
}

func getNextEp(prev *epoch, sigPk cryptoffi.SigPublicKey, chainProof, sig []byte) (next *epoch, err bool) {
	extLen, nextDig, nextLink, err := hashchain.Verify(prev.link, chainProof)
	if err {
		return
	}
	nextEp := prev.epoch + extLen
	if !std.SumNoOverflow(prev.epoch, extLen) {
		err = true
		return
	}
	if ktcore.VerifyLinkSig(sigPk, nextEp, nextLink, sig) {
		err = true
		return
	}
	if extLen == 0 {
		nextDig = prev.dig
	}
	next = &epoch{epoch: nextEp, dig: nextDig, link: nextLink, sig: sig}
	return
}

func checkMembs(vrfPk *cryptoffi.VrfPublicKey, uid, prefixLen uint64, dig []byte, hist []*ktcore.Memb) (err bool) {
	for ver, memb := range hist {
		if err = checkMemb(vrfPk, uid, prefixLen+uint64(ver), dig, memb); err {
			return
		}
	}
	return
}

func checkMemb(vrfPk *cryptoffi.VrfPublicKey, uid, ver uint64, dig []byte, memb *ktcore.Memb) (err bool) {
	label, err := ktcore.CheckMapLabel(vrfPk, uid, ver, memb.LabelProof)
	if err {
		return
	}
	mapVal := ktcore.GetMapVal(memb.PkOpen.Val, memb.PkOpen.Rand)
	dig0, err := merkle.VerifyMemb(label, mapVal, memb.MerkleProof)
	if err {
		return
	}
	if !bytes.Equal(dig, dig0) {
		err = true
		return
	}
	return
}

func checkNonMemb(vrfPk *cryptoffi.VrfPublicKey, uid, ver uint64, dig []byte, nonMemb *ktcore.NonMemb) (err bool) {
	label, err := ktcore.CheckMapLabel(vrfPk, uid, ver, nonMemb.LabelProof)
	if err {
		return
	}
	dig0, err := merkle.VerifyNonMemb(label, nonMemb.MerkleProof)
	if err {
		return
	}
	if !bytes.Equal(dig, dig0) {
		err = true
		return
	}
	return
}

func checkAuditLink(servPk, adtrPk cryptoffi.SigPublicKey, ep uint64, link *auditor.SignedLink) (err bool) {
	if ktcore.VerifyLinkSig(adtrPk, ep, link.Link, link.AdtrSig) {
		return true
	}
	if ktcore.VerifyLinkSig(servPk, ep, link.Link, link.ServSig) {
		return true
	}
	return
}

func checkAuditVrf(servPk, adtrPk cryptoffi.SigPublicKey, vrf *auditor.SignedVrf) (err bool) {
	if ktcore.VerifyVrfSig(adtrPk, vrf.VrfPk, vrf.AdtrSig) {
		return true
	}
	if ktcore.VerifyVrfSig(servPk, vrf.VrfPk, vrf.ServSig) {
		return true
	}
	return
}
