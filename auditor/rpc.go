package auditor

import (
	"github.com/sanjit-bhat/pav/advrpc"
	"github.com/sanjit-bhat/pav/ktcore"
)

const (
	GetRpc uint64 = iota
)

func NewRpcAuditor(adtr *Auditor) *advrpc.Server {
	h := make(map[uint64]func([]byte, *[]byte))
	h[GetRpc] = func(arg []byte, reply *[]byte) {
		a, _, err := GetArgDecode(arg)
		if err {
			r := &GetReply{Err: true}
			*reply = GetReplyEncode(*reply, r)
			return
		}
		r0, r1, r2 := adtr.Get(a.Epoch)
		r := &GetReply{Link: r0, Vrf: r1, Err: r2}
		*reply = GetReplyEncode(*reply, r)
	}
	return advrpc.NewServer(h)
}

func CallGet(c *advrpc.Client, epoch uint64) (link *SignedLink, vrf *SignedVrf, err ktcore.Blame) {
	a := &GetArg{Epoch: epoch}
	ab := GetArgEncode(nil, a)
	rb := new([]byte)
	if c.Call(GetRpc, ab, rb) {
		err = ktcore.BlameUnknown
		return
	}
	r, _, errb := GetReplyDecode(*rb)
	link = r.Link
	vrf = r.Vrf
	if errb {
		err = ktcore.BlameAdtr
		return
	}
	if r.Err {
		// [Get] legitimately returns errs.
		err = ktcore.BlameUnknown
		return
	}
	return
}
