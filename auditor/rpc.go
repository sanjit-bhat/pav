package auditor

import (
	"github.com/mit-pdos/pav/advrpc"
	"github.com/mit-pdos/pav/ktserde"
)

const (
	UpdateRpc uint64 = 1
	GetRpc    uint64 = 2
)

func NewRpcAuditor(adtr *Auditor) *advrpc.Server {
	h := make(map[uint64]func([]byte, *[]byte))
	h[UpdateRpc] = func(arg []byte, reply *[]byte) {
		a, _, err0 := UpdateArgDecode(arg)
		if err0 {
			return
		}
		r0 := adtr.Update(a.P)
		replyObj := &UpdateReply{Err: r0}
		*reply = UpdateReplyEncode(*reply, replyObj)
	}
	h[GetRpc] = func(arg []byte, reply *[]byte) {
		a, _, err0 := GetArgDecode(arg)
		if err0 {
			return
		}
		r0, r1 := adtr.Get(a.Epoch)
		r := &GetReply{X: r0, Err: r1}
		*reply = GetReplyEncode(*reply, r)
	}
	return advrpc.NewServer(h)
}

func CallUpdate(c *advrpc.Client, proof *ktserde.AuditProof) bool {
	a := &UpdateArg{P: proof}
	ab := UpdateArgEncode(make([]byte, 0), a)
	rb := new([]byte)
	var err0 = true
	for err0 {
		err0 = c.Call(UpdateRpc, ab, rb)
	}
	r, _, err1 := UpdateReplyDecode(*rb)
	if err1 {
		return true
	}
	return r.Err
}

func CallGet(c *advrpc.Client, epoch uint64) (*EpochInfo, bool) {
	var info *EpochInfo
	var err bool
	// retry net and invalid-epoch errs:
	// client can't assert that adtr has requested epoch.
	// pass thru decoding err, which client can assert away in correctness world.
	// NOTE: malicious server could send a very large epoch to the client,
	// causing it to infinite loop, but this is a bigger liveness bug.
	for {
		info0, err0 := callGetAux(c, epoch)
		info = info0
		if err0 == errNone {
			break
		}
		if err0 == errDecode {
			err = true
			break
		}
	}
	return info, err
}

const (
	errNone   uint64 = 1
	errNet    uint64 = 2
	errDecode uint64 = 3
	errAdtr   uint64 = 4
)

func callGetAux(c *advrpc.Client, epoch uint64) (*EpochInfo, uint64) {
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
	return r.X, errNone
}
