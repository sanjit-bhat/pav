package kt

import (
	"github.com/mit-pdos/pav/advrpc"
)

const (
	ServerPutRpc     uint64 = 0
	ServerGetRpc     uint64 = 1
	ServerSelfMonRpc uint64 = 2
	ServerAuditRpc   uint64 = 3
	AdtrUpdateRpc    uint64 = 0
	AdtrGetRpc       uint64 = 1
)

func NewRpcServer(s *Server) *advrpc.Server {
	h := make(map[uint64]func([]byte, *[]byte))
	h[ServerPutRpc] = func(arg []byte, reply *[]byte) {
		argObj, _, err0 := ServerPutArgDecode(arg)
		if err0 {
			return
		}
		ret0, ret1, ret2, ret3 := s.Put(argObj.Uid, argObj.Pk)
		replyObj := &ServerPutReply{Dig: ret0, Latest: ret1, Bound: ret2, Err: ret3}
		*reply = ServerPutReplyEncode(*reply, replyObj)
	}
	h[ServerGetRpc] = func(arg []byte, reply *[]byte) {
		argObj, _, err0 := ServerGetArgDecode(arg)
		if err0 {
			return
		}
		ret0, ret1, ret2, ret3, ret4 := s.Get(argObj.Uid)
		replyObj := &ServerGetReply{Dig: ret0, Hist: ret1, IsReg: ret2, Latest: ret3, Bound: ret4}
		*reply = ServerGetReplyEncode(*reply, replyObj)
	}
	h[ServerSelfMonRpc] = func(arg []byte, reply *[]byte) {
		argObj, _, err0 := ServerSelfMonArgDecode(arg)
		if err0 {
			return
		}
		ret0, ret1 := s.SelfMon(argObj.Uid)
		replyObj := &ServerSelfMonReply{Dig: ret0, Bound: ret1}
		*reply = ServerSelfMonReplyEncode(*reply, replyObj)
	}
	h[ServerAuditRpc] = func(arg []byte, reply *[]byte) {
		argObj, _, err0 := ServerAuditArgDecode(arg)
		if err0 {
			return
		}
		ret0, ret1 := s.Audit(argObj.Epoch)
		replyObj := &ServerAuditReply{P: ret0, Err: ret1}
		*reply = ServerAuditReplyEncode(*reply, replyObj)
	}
	return advrpc.NewServer(h)
}

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

func CallServPut(c *advrpc.Client, uid uint64, pk []byte) (*SigDig, *Memb, *NonMemb, bool) {
	arg := &ServerPutArg{Uid: uid, Pk: pk}
	argByt := ServerPutArgEncode(make([]byte, 0), arg)
	replyByt := new([]byte)
	var err0 = true
	for err0 {
		// this "removes" possibility of net failure.
		// should prob have some retry backoff mechanism.
		err0 = c.Call(ServerPutRpc, argByt, replyByt)
	}
	reply, _, err1 := ServerPutReplyDecode(*replyByt)
	if err1 {
		return nil, nil, nil, true
	}
	return reply.Dig, reply.Latest, reply.Bound, reply.Err
}

func CallServGet(c *advrpc.Client, uid uint64) (*SigDig, []*MembHide, bool, *Memb, *NonMemb, bool) {
	arg := &ServerGetArg{Uid: uid}
	argByt := ServerGetArgEncode(make([]byte, 0), arg)
	replyByt := new([]byte)
	var err0 = true
	for err0 {
		err0 = c.Call(ServerGetRpc, argByt, replyByt)
	}
	reply, _, err1 := ServerGetReplyDecode(*replyByt)
	if err1 {
		return nil, nil, false, nil, nil, true
	}
	return reply.Dig, reply.Hist, reply.IsReg, reply.Latest, reply.Bound, false
}

func CallServSelfMon(c *advrpc.Client, uid uint64) (*SigDig, *NonMemb, bool) {
	arg := &ServerSelfMonArg{Uid: uid}
	argByt := ServerSelfMonArgEncode(make([]byte, 0), arg)
	replyByt := new([]byte)
	var err0 = true
	for err0 {
		err0 = c.Call(ServerSelfMonRpc, argByt, replyByt)
	}
	reply, _, err1 := ServerSelfMonReplyDecode(*replyByt)
	if err1 {
		return nil, nil, true
	}
	return reply.Dig, reply.Bound, false
}

func CallServAudit(c *advrpc.Client, epoch uint64) (*UpdateProof, bool) {
	arg := &ServerAuditArg{Epoch: epoch}
	argByt := ServerAuditArgEncode(make([]byte, 0), arg)
	replyByt := new([]byte)
	var err0 = true
	for err0 {
		err0 = c.Call(ServerAuditRpc, argByt, replyByt)
	}
	reply, _, err1 := ServerAuditReplyDecode(*replyByt)
	if err1 {
		return nil, true
	}
	return reply.P, reply.Err
}

func CallAdtrUpdate(c *advrpc.Client, proof *UpdateProof) bool {
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
