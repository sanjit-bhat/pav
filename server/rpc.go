package server

import (
	"github.com/mit-pdos/pav/advrpc"
	"github.com/mit-pdos/pav/ktserde"
)

const (
	ServerPutRpc     uint64 = 0
	ServerGetRpc     uint64 = 1
	ServerSelfMonRpc uint64 = 2
	ServerAuditRpc   uint64 = 3
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

func CallServPut(c *advrpc.Client, uid uint64, pk []byte) (*ktserde.SigDig, *ktserde.Memb, *ktserde.NonMemb, bool) {
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

func CallServGet(c *advrpc.Client, uid uint64) (*ktserde.SigDig, []*ktserde.MembHide, bool, *ktserde.Memb, *ktserde.NonMemb, bool) {
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

func CallServSelfMon(c *advrpc.Client, uid uint64) (*ktserde.SigDig, *ktserde.NonMemb, bool) {
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

func CallServAudit(c *advrpc.Client, epoch uint64) (*ktserde.UpdateProof, bool) {
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
