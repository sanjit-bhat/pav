package auditor

import (
	"github.com/mit-pdos/pav/advrpc"
	"github.com/mit-pdos/pav/ktserde"
)

const (
	AdtrUpdateRpc uint64 = 0
	AdtrGetRpc    uint64 = 1
)

func NewRpcAuditor(a *Auditor) *advrpc.Server {
	h := make(map[uint64]func([]byte, *[]byte))
	h[AdtrUpdateRpc] = func(arg []byte, reply *[]byte) {
		argObj, _, err0 := AdtrUpdateArgDecode(arg)
		if err0 {
			return
		}
		ret0 := a.Update(argObj.P)
		replyObj := &AdtrUpdateReply{Err: ret0}
		*reply = AdtrUpdateReplyEncode(*reply, replyObj)
	}
	h[AdtrGetRpc] = func(arg []byte, reply *[]byte) {
		argObj, _, err0 := AdtrGetArgDecode(arg)
		if err0 {
			return
		}
		ret0, ret1 := a.Get(argObj.Epoch)
		replyObj := &AdtrGetReply{X: ret0, Err: ret1}
		*reply = AdtrGetReplyEncode(*reply, replyObj)
	}
	return advrpc.NewServer(h)
}

func CallAdtrUpdate(c *advrpc.Client, proof *ktserde.UpdateProof) bool {
	arg := &AdtrUpdateArg{P: proof}
	argByt := AdtrUpdateArgEncode(make([]byte, 0), arg)
	replyByt := new([]byte)
	var err0 = true
	for err0 {
		err0 = c.Call(AdtrUpdateRpc, argByt, replyByt)
	}
	reply, _, err1 := AdtrUpdateReplyDecode(*replyByt)
	if err1 {
		return true
	}
	return reply.Err
}

func CallAdtrGet(c *advrpc.Client, epoch uint64) *AdtrEpochInfo {
	var adtrInfo *AdtrEpochInfo
	var err = true
	// this "removes" errors from the auditor, which arise from
	// not yet having seen an epoch.
	// this allows us to prove that client.Audit never errors
	// in a correctness setting.
	// a malicious server could send a very large epoch to the client,
	// causing it to infinitely loop.
	for err {
		adtrInfo0, err0 := callAdtrGetInner(c, epoch)
		adtrInfo = adtrInfo0
		err = err0
	}
	return adtrInfo
}

func callAdtrGetInner(c *advrpc.Client, epoch uint64) (*AdtrEpochInfo, bool) {
	arg := &AdtrGetArg{Epoch: epoch}
	argByt := AdtrGetArgEncode(make([]byte, 0), arg)
	replyByt := new([]byte)
	var err0 = true
	for err0 {
		err0 = c.Call(AdtrGetRpc, argByt, replyByt)
	}
	reply, _, err1 := AdtrGetReplyDecode(*replyByt)
	if err1 {
		return nil, true
	}
	return reply.X, reply.Err
}
