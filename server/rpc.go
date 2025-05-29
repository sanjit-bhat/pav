package server

import (
	"github.com/mit-pdos/pav/advrpc"
	"github.com/mit-pdos/pav/ktserde"
)

const (
	ServerPutRpc     uint64 = 0
	ServerHistoryRpc uint64 = 1
	ServerAuditRpc   uint64 = 2
)

func NewRpcServer(s *Server) *advrpc.Server {
	h := make(map[uint64]func([]byte, *[]byte))
	h[ServerPutRpc] = func(arg []byte, reply *[]byte) {
		argObj, _, err0 := ServerPutArgDecode(arg)
		if err0 {
			return
		}
		s.Put(argObj.Uid, argObj.Pk, argObj.Ver)
		*reply = nil
	}
	h[ServerHistoryRpc] = func(arg []byte, reply *[]byte) {
		argObj, _, err0 := ServerHistoryArgDecode(arg)
		if err0 {
			return
		}
		ret0, ret1, ret2, ret3 := s.History(argObj.Uid, argObj.PrefixLen)
		replyObj := &ServerHistoryReply{Dig: ret0, Hist: ret1, Bound: ret2, Err: ret3}
		*reply = ServerHistoryReplyEncode(*reply, replyObj)
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

func CallServPut(c *advrpc.Client, uid uint64, pk []byte, ver uint64) {
	arg := &ServerPutArg{Uid: uid, Pk: pk, Ver: ver}
	argByt := ServerPutArgEncode(make([]byte, 0), arg)
	replyByt := new([]byte)
	var err0 = true
	for err0 {
		// this "removes" possibility of net failure.
		err0 = c.Call(ServerPutRpc, argByt, replyByt)
	}
}

func CallServHistory(c *advrpc.Client, uid uint64, prefixLen uint64) (*ktserde.SigDig, []*ktserde.Memb, *ktserde.NonMemb, bool) {
	arg := &ServerHistoryArg{Uid: uid, PrefixLen: prefixLen}
	argByt := ServerHistoryArgEncode(make([]byte, 0), arg)
	replyByt := new([]byte)
	var err0 = true
	for err0 {
		err0 = c.Call(ServerHistoryRpc, argByt, replyByt)
	}
	reply, _, err1 := ServerHistoryReplyDecode(*replyByt)
	if err1 {
		return nil, nil, nil, true
	}
	return reply.Dig, reply.Hist, reply.Bound, false
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
