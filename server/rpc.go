package server

import (
	"github.com/mit-pdos/pav/advrpc"
	"github.com/mit-pdos/pav/ktserde"
)

const (
	StartCliRpc uint64 = 1
	PutRpc      uint64 = 2
	HistoryRpc  uint64 = 3
	AuditRpc    uint64 = 4
)

func NewRpcServer(s *Server) *advrpc.Server {
	h := make(map[uint64]func([]byte, *[]byte))
	h[StartCliRpc] = func(arg []byte, reply *[]byte) {
		r0, r1, r2, r3 := s.StartCli()
		r := &StartCliReply{StartEpochLen: r0, StartLink: r1, ChainProof: r2, LinkSig: r3}
		*reply = StartCliReplyEncode(*reply, r)
	}
	h[PutRpc] = func(arg []byte, reply *[]byte) {
		a, _, err0 := PutArgDecode(arg)
		if err0 {
			return
		}
		s.Put(a.Uid, a.Pk, a.Ver)
		*reply = nil
	}
	h[HistoryRpc] = func(arg []byte, reply *[]byte) {
		a, _, err0 := HistoryArgDecode(arg)
		if err0 {
			return
		}
		r0, r1, r2, r3, r4 := s.History(a.Uid, a.PrevEpoch, a.PrevVerLen)
		r := &HistoryReply{ChainProof: r0, LinkSig: r1, Hist: r2, Bound: r3, Err: r4}
		*reply = HistoryReplyEncode(*reply, r)
	}
	h[AuditRpc] = func(arg []byte, reply *[]byte) {
		a, _, err0 := AuditArgDecode(arg)
		if err0 {
			return
		}
		r0, r1 := s.Audit(a.Epoch)
		r := &AuditReply{P: r0, Err: r1}
		*reply = AuditReplyEncode(*reply, r)
	}
	return advrpc.NewServer(h)
}

// in below, loop on calls to "remove" possibility of net failure.
// in correctness world, all remaining errors (including reply decoding)
// come from server code.
// client should be able to assert that they don't happen.

func CallStartCli(c *advrpc.Client) (uint64, []byte, []byte, []byte, bool) {
	rb := new([]byte)
	var err0 = true
	for err0 {
		err0 = c.Call(StartCliRpc, nil, rb)
	}
	r, _, err1 := StartCliReplyDecode(*rb)
	if err1 {
		return 0, nil, nil, nil, true
	}
	return r.StartEpochLen, r.StartLink, r.ChainProof, r.LinkSig, false
}

func CallPut(c *advrpc.Client, uid uint64, pk []byte, ver uint64) {
	a := &PutArg{Uid: uid, Pk: pk, Ver: ver}
	ab := PutArgEncode(make([]byte, 0), a)
	rb := new([]byte)
	var err0 = true
	for err0 {
		err0 = c.Call(PutRpc, ab, rb)
	}
}

func CallHistory(c *advrpc.Client, uid, prevEpoch, prevVerLen uint64) ([]byte, []byte, []*ktserde.Memb, *ktserde.NonMemb, bool) {
	a := &HistoryArg{Uid: uid, PrevEpoch: prevEpoch, PrevVerLen: prevVerLen}
	ab := HistoryArgEncode(make([]byte, 0), a)
	rb := new([]byte)
	var err0 = true
	for err0 {
		err0 = c.Call(HistoryRpc, ab, rb)
	}
	r, _, err1 := HistoryReplyDecode(*rb)
	if err1 {
		return nil, nil, nil, nil, true
	}
	return r.ChainProof, r.LinkSig, r.Hist, r.Bound, r.Err
}

func CallAudit(c *advrpc.Client, epoch uint64) (*ktserde.AuditProof, bool) {
	a := &AuditArg{Epoch: epoch}
	ab := AuditArgEncode(make([]byte, 0), a)
	rb := new([]byte)
	var err0 = true
	for err0 {
		err0 = c.Call(AuditRpc, ab, rb)
	}
	r, _, err1 := AuditReplyDecode(*rb)
	if err1 {
		return nil, true
	}
	return r.P, r.Err
}
