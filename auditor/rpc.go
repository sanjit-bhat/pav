package auditor

import (
	"github.com/mit-pdos/pav/advrpc"
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
			return
		}
		r := adtr.Get(a.Epoch)
		*reply = GetReplyEncode(*reply, r)
	}
	return advrpc.NewServer(h)
}

func CallUpdate(c *advrpc.Client) bool {
	rb := new([]byte)
	var err0 = true
	for err0 {
		err0 = c.Call(UpdateRpc, nil, rb)
	}
	r, _, err1 := UpdateReplyDecode(*rb)
	if err1 {
		return true
	}
	return r.Err
}

func CallGet(c *advrpc.Client, epoch uint64) *GetReply {
	var reply *GetReply
	// retry net and invalid-epoch errs:
	// client can't assert that adtr has requested epoch.
	// pass thru decoding err, which client can assert away in correctness world.
	// NOTE: malicious server could send a very large epoch to the client,
	// causing it to infinite loop, but this is a bigger liveness bug.
	for {
		reply0, err0 := callGetAux(c, epoch)
		reply = reply0
		if err0 == errNone {
			break
		}
		if err0 == errDecode {
			break
		}
	}
	return reply
}

const (
	errNone   uint64 = 1
	errNet    uint64 = 2
	errDecode uint64 = 3
	errAdtr   uint64 = 4
)

func callGetAux(c *advrpc.Client, epoch uint64) (*GetReply, uint64) {
	a := &GetArg{Epoch: epoch}
	ab := GetArgEncode(make([]byte, 0), a)
	rb := new([]byte)
	err0 := c.Call(GetRpc, ab, rb)
	if err0 {
		return nil, errNet
	}
	r, _, err1 := GetReplyDecode(*rb)
	if err1 {
		return nil, errDecode
	}
	if r.Err {
		return nil, errAdtr
	}
	return r, errNone
}
