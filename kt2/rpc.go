package kt2

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

func newRPCServer(s *Server) *advrpc.Server {
	h := make(map[uint64]func([]byte, *[]byte))
	h[ServerPutRpc] = func(arg []byte, reply *[]byte) {
		argObj, _, err0 := ServerPutArgDecode(arg)
		if err0 {
			return
		}
		ret0, ret1, ret2 := s.Put(argObj.Uid, argObj.Pk)
		replyObj := &ServerPutReply{Dig: ret0, Latest: ret1, Bound: ret2}
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

func newRPCAuditor(a *Auditor) *advrpc.Server {
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

func callServPut(c *advrpc.Client, uid uint64, pk []byte) (*SigDig, *Memb, *NonMemb, bool) {
	arg := &ServerPutArg{Uid: uid, Pk: pk}
	argByt := ServerPutArgEncode(make([]byte, 0), arg)
	replyByt := new([]byte)
	err0 := c.Call(ServerPutRpc, argByt, replyByt)
	if err0 {
		return nil, nil, nil, true
	}
	reply, _, err1 := ServerPutReplyDecode(*replyByt)
	if err1 {
		return nil, nil, nil, true
	}
	return reply.Dig, reply.Latest, reply.Bound, false
}

func callServGet(c *advrpc.Client, uid uint64) (*SigDig, []*MembHide, bool, *Memb, *NonMemb, bool) {
	arg := &ServerGetArg{Uid: uid}
	argByt := ServerGetArgEncode(make([]byte, 0), arg)
	replyByt := new([]byte)
	err0 := c.Call(ServerGetRpc, argByt, replyByt)
	if err0 {
		return nil, nil, false, nil, nil, true
	}
	reply, _, err1 := ServerGetReplyDecode(*replyByt)
	if err1 {
		return nil, nil, false, nil, nil, true
	}
	return reply.Dig, reply.Hist, reply.IsReg, reply.Latest, reply.Bound, false
}

func callServSelfMon(c *advrpc.Client, uid uint64) (*SigDig, *NonMemb, bool) {
	arg := &ServerSelfMonArg{Uid: uid}
	argByt := ServerSelfMonArgEncode(make([]byte, 0), arg)
	replyByt := new([]byte)
	err0 := c.Call(ServerSelfMonRpc, argByt, replyByt)
	if err0 {
		return nil, nil, true
	}
	reply, _, err1 := ServerSelfMonReplyDecode(*replyByt)
	if err1 {
		return nil, nil, true
	}
	return reply.Dig, reply.Bound, false
}

func callServAudit(c *advrpc.Client, epoch uint64) (*UpdateProof, bool) {
	arg := &ServerAuditArg{Epoch: epoch}
	argByt := ServerAuditArgEncode(make([]byte, 0), arg)
	replyByt := new([]byte)
	err0 := c.Call(ServerAuditRpc, argByt, replyByt)
	if err0 {
		return nil, true
	}
	reply, _, err1 := ServerAuditReplyDecode(*replyByt)
	if err1 {
		return nil, true
	}
	// since our clients don't currently distinguish server vs. net errs,
	// it seems fine to combine the err spaces.
	return reply.P, reply.Err
}

func callAdtrUpdate(c *advrpc.Client, proof *UpdateProof) bool {
	arg := &AdtrUpdateArg{P: proof}
	argByt := AdtrUpdateArgEncode(make([]byte, 0), arg)
	replyByt := new([]byte)
	err0 := c.Call(AdtrUpdateRpc, argByt, replyByt)
	if err0 {
		return true
	}
	reply, _, err1 := AdtrUpdateReplyDecode(*replyByt)
	if err1 {
		return true
	}
	return reply.Err
}

func callAdtrGet(c *advrpc.Client, epoch uint64) (*AdtrEpochInfo, bool) {
	arg := &AdtrGetArg{Epoch: epoch}
	argByt := AdtrGetArgEncode(make([]byte, 0), arg)
	replyByt := new([]byte)
	err0 := c.Call(AdtrGetRpc, argByt, replyByt)
	if err0 {
		return nil, true
	}
	reply, _, err1 := AdtrGetReplyDecode(*replyByt)
	if err1 {
		return nil, true
	}
	return reply.X, reply.Err
}
