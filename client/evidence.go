package client

import (
	"github.com/goose-lang/std"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/ktserde"
)

// Check rets err if signed dig does not validate.
func CheckSigDig(o *ktserde.SigDig, pk cryptoffi.SigPublicKey) bool {
	pre := &ktserde.PreSigDig{Epoch: o.Epoch, Dig: o.Dig}
	preByt := ktserde.PreSigDigEncode(make([]byte, 0), pre)
	return pk.Verify(preByt, o.Sig)
}

// Evid is evidence that the server signed two conflicting digs.
type Evid struct {
	sigDig0 *ktserde.SigDig
	sigDig1 *ktserde.SigDig
}

// Check returns an error if the evidence does not check out.
// otherwise, it proves that the server was dishonest.
func (e *Evid) Check(servPk cryptoffi.SigPublicKey) bool {
	err0 := CheckSigDig(e.sigDig0, servPk)
	if err0 {
		return true
	}
	err1 := CheckSigDig(e.sigDig1, servPk)
	if err1 {
		return true
	}
	if e.sigDig0.Epoch != e.sigDig1.Epoch {
		return true
	}
	return std.BytesEqual(e.sigDig0.Dig, e.sigDig1.Dig)
}
