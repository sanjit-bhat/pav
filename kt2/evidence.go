package kt2

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/merkle"
)

type SignedLink struct {
	epoch    epochTy
	prevLink linkTy
	dig      merkle.Digest
	sig      cryptoffi.Sig
}

func (o *SignedLink) check(pk cryptoffi.PublicKey) (linkTy, errorTy) {
	link := nextLink(o.epoch, o.prevLink, o.dig)
	ok0 := pk.Verify(link, o.sig)
	return link, !ok0
}

// Evid is evidence that the server signed two conflicting links,
// either zero or one epochs away.
type Evid struct {
	sigLn0 *SignedLink
	sigLn1 *SignedLink
}

// Check returns an error if the evidence does not Check out.
// otherwise, it proves that the server was dishonest.
func (e *Evid) Check(servPk cryptoffi.PublicKey) errorTy {
	link0, err0 := e.sigLn0.check(servPk)
	if err0 {
		return true
	}

	link1, err1 := e.sigLn1.check(servPk)
	if err1 {
		return true
	}

	if e.sigLn0.epoch == e.sigLn1.epoch {
		return std.BytesEqual(link0, link1)
	}
	if e.sigLn1.epoch > 0 && e.sigLn0.epoch == e.sigLn1.epoch-1 {
		return std.BytesEqual(link0, e.sigLn1.prevLink)
	}
	return true
}
