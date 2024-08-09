package ktmerkle

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/merkle"
)

type signedLink struct {
	epoch    epochTy
	prevLink linkTy
	dig      merkle.Digest
	sig      cryptoffi.Sig
}

func (o *signedLink) check(pk cryptoffi.PublicKey) (linkTy, errorTy) {
	preLink := (&chainSepSome{epoch: o.epoch, prevLink: o.prevLink, data: o.dig}).encode()
	link := cryptoffi.Hash(preLink)
	sepLink := (&servSepLink{link: link}).encode()
	ok := pk.Verify(sepLink, o.sig)
	return link, !ok
}

type signedPut struct {
	epoch epochTy
	id    merkle.Id
	val   merkle.Val
	sig   cryptoffi.Sig
}

func (o *signedPut) check(pk cryptoffi.PublicKey) errorTy {
	sepPut := (&servSepPut{epoch: o.epoch, id: o.id, val: o.val}).encode()
	okPut := pk.Verify(sepPut, o.sig)
	return !okPut
}

// evidServLink is evidence that the server signed two conflicting links,
// either zero or one epochs away.
type evidServLink struct {
	sln0 *signedLink
	sln1 *signedLink
}

// check returns an error if the evidence does not check out.
// otherwise, it proves that the server was dishonest.
func (e *evidServLink) check(servPk cryptoffi.PublicKey) errorTy {
	link0, err0 := e.sln0.check(servPk)
	if err0 {
		return errSome
	}

	link1, err1 := e.sln1.check(servPk)
	if err1 {
		return errSome
	}

	if e.sln0.epoch == e.sln1.epoch {
		return std.BytesEqual(link0, link1)
	}
	if e.sln0.epoch == e.sln1.epoch-1 {
		return std.BytesEqual(link0, e.sln1.prevLink)
	}
	return errSome
}

// evidServPut is evidence when a server promises to put a value at a certain
// epoch but actually there's a different value (as evidenced by a merkle proof).
type evidServPut struct {
	sln *signedLink
	sp  *signedPut
	// merkle inclusion.
	val   merkle.Val
	proof merkle.Proof
}

func (e *evidServPut) check(servPk cryptoffi.PublicKey) errorTy {
	_, err0 := e.sln.check(servPk)
	if err0 {
		return errSome
	}

	err1 := e.sp.check(servPk)
	if err1 {
		return errSome
	}

	// merkle inclusion of the other val.
	err2 := merkle.CheckProof(merkle.MembProofTy, e.proof, e.sp.id, e.val, e.sln.dig)
	if err2 {
		return errSome
	}

	if e.sln.epoch != e.sp.epoch {
		return errSome
	}
	return std.BytesEqual(e.sp.val, e.val)
}
