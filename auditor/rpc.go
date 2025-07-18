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
			r := &GetReply{Err: ktcore.BlameUnknown}
			*reply = GetReplyEncode(*reply, r)
			return
		}
		r := adtr.Get(a.Epoch)
		*reply = GetReplyEncode(*reply, r)
	}
	return advrpc.NewServer(h)
}

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

func CallGet(c *advrpc.Client, epoch uint64) *GetReply {
	a := &GetArg{Epoch: epoch}
	ab := GetArgEncode(nil, a)
	rb := new([]byte)
	if c.Call(GetRpc, ab, rb) {
		return &GetReply{Err: ktcore.BlameUnknown}
	}
	r, _, errb := GetReplyDecode(*rb)
	if errb {
		return &GetReply{Err: ktcore.BlameAdtrFull}
	}
	if ktcore.CheckBlame(r.Err, []ktcore.Blame{ktcore.BlameUnknown}) {
		return &GetReply{Err: ktcore.BlameAdtrFull}
	}
	return r
}
