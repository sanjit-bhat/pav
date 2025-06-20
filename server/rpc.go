package server

import (
	"github.com/mit-pdos/pav/advrpc"
	"github.com/mit-pdos/pav/ktcore"
)

const (
	StartRpc   uint64 = 1
	PutRpc     uint64 = 2
	HistoryRpc uint64 = 3
	AuditRpc   uint64 = 4
)

func NewRpcServer(s *Server) *advrpc.Server {
	h := make(map[uint64]func([]byte, *[]byte))
	h[StartRpc] = func(arg []byte, reply *[]byte) {
		r := s.Start()
		*reply = StartReplyEncode(*reply, r)
	}
	h[PutRpc] = func(arg []byte, reply *[]byte) {
		a, _, err0 := PutArgDecode(arg)
		if err0 {
			// would blame client, except that Put client doesn't care.
			return
		}
		s.Put(a.Uid, a.Pk, a.Ver)
		*reply = nil
	}
	h[HistoryRpc] = func(arg []byte, reply *[]byte) {
		a, _, err0 := HistoryArgDecode(arg)
		if err0 {
			r := &HistoryReply{Err: ktcore.BlameClients}
			*reply = HistoryReplyEncode(*reply, r)
			return
		}
		r0, r1, r2, r3, r4 := s.History(a.Uid, a.PrevEpoch, a.PrevVerLen)
		r := &HistoryReply{ChainProof: r0, LinkSig: r1, Hist: r2, Bound: r3, Err: r4}
		*reply = HistoryReplyEncode(*reply, r)
	}
	h[AuditRpc] = func(arg []byte, reply *[]byte) {
		a, _, err0 := AuditArgDecode(arg)
		if err0 {
			r := &AuditReply{Err: ktcore.BlameAuditors}
			*reply = AuditReplyEncode(*reply, r)
			return
		}
		r0, r1 := s.Audit(a.PrevEpochLen)
		r := &AuditReply{P: r0, Err: r1}
		*reply = AuditReplyEncode(*reply, r)
	}
	return advrpc.NewServer(h)
}

/*
Call* methods are run by the caller.
a good caller knows that they gave good inputs,
so after the potential for net and decoding errors,
they check that there's no more blame.
*/

func CallStart(c *advrpc.Client) (*StartReply, ktcore.Blame) {
	rb := new([]byte)
	if c.Call(StartRpc, nil, rb) {
		return nil, ktcore.BlameNet
	}
	r, _, err0 := StartReplyDecode(*rb)
	if err0 {
		return nil, ktcore.BlameServer
	}
	return r, ktcore.BlameNone
}

func CallPut(c *advrpc.Client, uid uint64, pk []byte, ver uint64) {
	a := &PutArg{Uid: uid, Pk: pk, Ver: ver}
	ab := PutArgEncode(make([]byte, 0), a)
	rb := new([]byte)
	// don't check Put errs bc caller doesn't care to know.
	c.Call(PutRpc, ab, rb)
}

func CallHistory(c *advrpc.Client, uid, prevEpoch, prevVerLen uint64) ([]byte, []byte, []*ktcore.Memb, *ktcore.NonMemb, ktcore.Blame) {
	a := &HistoryArg{Uid: uid, PrevEpoch: prevEpoch, PrevVerLen: prevVerLen}
	ab := HistoryArgEncode(make([]byte, 0), a)
	rb := new([]byte)
	if c.Call(HistoryRpc, ab, rb) {
		return nil, nil, nil, nil, ktcore.BlameNet
	}
	r, _, err0 := HistoryReplyDecode(*rb)
	if err0 {
		return nil, nil, nil, nil, ktcore.BlameServer
	}
	if ktcore.CheckBlame(r.Err, []ktcore.Blame{}) {
		return nil, nil, nil, nil, ktcore.BlameServer
	}
	return r.ChainProof, r.LinkSig, r.Hist, r.Bound, ktcore.BlameNone
}

func CallAudit(c *advrpc.Client, prevEpochLen uint64) ([]*ktcore.AuditProof, ktcore.Blame) {
	a := &AuditArg{PrevEpochLen: prevEpochLen}
	ab := AuditArgEncode(make([]byte, 0), a)
	rb := new([]byte)
	if c.Call(AuditRpc, ab, rb) {
		return nil, ktcore.BlameNet
	}
	r, _, err0 := AuditReplyDecode(*rb)
	if err0 {
		return nil, ktcore.BlameServer
	}
	if ktcore.CheckBlame(r.Err, []ktcore.Blame{}) {
		return nil, ktcore.BlameServer
	}
	return r.P, ktcore.BlameNone
}
