package auditor

import (
	"github.com/sanjit-bhat/pav/advrpc"
	"github.com/sanjit-bhat/pav/ktcore"
)

const (
	UpdateRpc uint64 = iota
	GetRpc
)

func NewRpcAuditor(adtr *Auditor) *advrpc.Server {
	h := make(map[uint64]func([]byte, *[]byte))
	h[UpdateRpc] = func(arg []byte, reply *[]byte) {
		r0 := adtr.Update()
		replyObj := &UpdateReply{Err: r0}
		*reply = UpdateReplyEncode(*reply, replyObj)
	}
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

// TODO: unclear if Update needs RPC interface.
// this could be an "internal" method call run in background.
func CallUpdate(c *advrpc.Client) (err ktcore.Blame) {
	rb := new([]byte)
	if c.Call(UpdateRpc, nil, rb) {
		return ktcore.BlameUnknown
	}
	r, _, errb := UpdateReplyDecode(*rb)
	if errb {
		return ktcore.BlameAdtrFull
	}
	// since Update calls and checks serv, might have these errs.
	if ktcore.CheckBlame(r.Err, []ktcore.Blame{ktcore.BlameServFull, ktcore.BlameUnknown}) {
		return ktcore.BlameAdtrFull
	}
	return
}

func CallGet(c *advrpc.Client, epoch uint64) (link *SignedLink, vrf *SignedVrfPk, err ktcore.Blame) {
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
		err = ktcore.BlameAdtrFull
		return
	}
	if r.Err {
		// [Get] legitimately returns errs.
		err = ktcore.BlameUnknown
		return
	}
	return
}
