package auditor

import (
	"github.com/mit-pdos/pav/advrpc"
	"github.com/mit-pdos/pav/ktcore"
)

const (
	UpdateRpc uint64 = 1
	GetRpc    uint64 = 2
)

func NewRpcAuditor(adtr *Auditor) *advrpc.Server {
	h := make(map[uint64]func([]byte, *[]byte))
	h[UpdateRpc] = func(arg []byte, reply *[]byte) {
		r0 := adtr.Update()
		replyObj := &UpdateReply{Err: r0}
		*reply = UpdateReplyEncode(*reply, replyObj)
	}
	h[GetRpc] = func(arg []byte, reply *[]byte) {
		a, _, err0 := GetArgDecode(arg)
		if err0 {
			r := &GetReply{Err: ktcore.BlameClients}
			*reply = GetReplyEncode(*reply, r)
			return
		}
		r := adtr.Get(a.Epoch)
		*reply = GetReplyEncode(*reply, r)
	}
	return advrpc.NewServer(h)
}

func CallUpdate(c *advrpc.Client) ktcore.Blame {
	rb := new([]byte)
	if c.Call(UpdateRpc, nil, rb) {
		return ktcore.BlameNet
	}
	r, _, err0 := UpdateReplyDecode(*rb)
	if err0 {
		return ktcore.BlameAuditors
	}
	// since Update calls and checks serv, might have these errs.
	if ktcore.CheckBlame(r.Err, []ktcore.Blame{ktcore.BlameNet, ktcore.BlameServer}) {
		return ktcore.BlameAuditors
	}
	return ktcore.BlameNone
}

func CallGet(c *advrpc.Client, epoch uint64) *GetReply {
	a := &GetArg{Epoch: epoch}
	ab := GetArgEncode(make([]byte, 0), a)
	rb := new([]byte)
	if c.Call(GetRpc, ab, rb) {
		return &GetReply{Err: ktcore.BlameNet}
	}
	r, _, err0 := GetReplyDecode(*rb)
	if err0 {
		return &GetReply{Err: ktcore.BlameAuditors}
	}
	if ktcore.CheckBlame(r.Err, []ktcore.Blame{ktcore.BlameUnknown}) {
		return &GetReply{Err: ktcore.BlameAuditors}
	}
	return r
}
