package auditor

import (
	"github.com/sanjit-bhat/pav/advrpc"
	"github.com/sanjit-bhat/pav/ktcore"
)

const (
	GetRpc uint64 = iota
)

func NewRpcServer(adtr *Auditor) *advrpc.Server {
	h := make(map[uint64]func([]byte, *[]byte))
	h[GetRpc] = func(arg []byte, reply *[]byte) {
		a, _, err := GetArgDecode(arg)
		if err {
			r := &GetReply{Err: true}
			*reply = GetReplyEncode(*reply, r)
			return
		}
		r0, r1, r2, r3, r4 := adtr.Get(a.Epoch)
		r := &GetReply{StartEp: r0, StartLink: r1, CurrLink: r2, Vrf: r3, Err: r4}
		*reply = GetReplyEncode(*reply, r)
	}
	return advrpc.NewServer(h)
}

func CallGet(c *advrpc.Client, epoch uint64) (startEp uint64, startLink, currLink *SignedLink, vrf *SignedVrf, err ktcore.Blame) {
	a := &GetArg{Epoch: epoch}
	ab := GetArgEncode(nil, a)
	rb := new([]byte)
	if c.Call(GetRpc, ab, rb) {
		err = ktcore.BlameUnknown
		return
	}
	r, _, errb := GetReplyDecode(*rb)
	if errb {
		err = ktcore.BlameAdtrFull
		return
	}
	startEp = r.StartEp
	startLink = r.StartLink
	currLink = r.CurrLink
	vrf = r.Vrf
	if r.Err {
		// [Get] legitimately returns errs.
		err = ktcore.BlameUnknown
		return
	}
	return
}
