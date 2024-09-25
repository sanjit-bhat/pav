package kt2

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/rpcffi"
)

// pre-img of digest signature.
type PreDigSig struct {
	Epoch uint64
	Dig   []byte
}

// signed digest.
type SigDig struct {
	Epoch uint64
	Dig   []byte
	Sig   []byte
}

// Check rets err if signed dig does not validate.
func (o *SigDig) Check(pk cryptoffi.PublicKey) bool {
	pre := &PreDigSig{Epoch: o.Epoch, Dig: o.Dig}
	preByt := rpcffi.Encode(pre)
	return !pk.Verify(preByt, o.Sig)
}

// Evid is evidence that the server signed two conflicting digs.
type Evid struct {
	sigDig0 *SigDig
	sigDig1 *SigDig
}

// Check returns an error if the evidence does not check out.
// otherwise, it proves that the server was dishonest.
func (e *Evid) Check(servPk cryptoffi.PublicKey) bool {
	err0 := e.sigDig0.Check(servPk)
	if err0 {
		return true
	}
	err1 := e.sigDig1.Check(servPk)
	if err1 {
		return true
	}
	if e.sigDig0.Epoch != e.sigDig1.Epoch {
		return true
	}
	return std.BytesEqual(e.sigDig0.Dig, e.sigDig1.Dig)
}
