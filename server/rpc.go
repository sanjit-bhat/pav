package server

import (
	"github.com/sanjit-bhat/pav/advrpc"
	"github.com/sanjit-bhat/pav/ktcore"
)

const (
	StartRpc uint64 = iota
	PutRpc
	HistoryRpc
	AuditRpc
)

func NewRpcServer(s *Server) *advrpc.Server {
	h := make(map[uint64]func([]byte, *[]byte))
	h[StartRpc] = func(arg []byte, reply *[]byte) {
		r0, r1 := s.Start()
		r := &StartReply{Chain: r0, Vrf: r1}
		*reply = StartReplyEncode(*reply, r)
	}
	h[PutRpc] = func(arg []byte, reply *[]byte) {
		a, _, err := PutArgDecode(arg)
		if err {
			// would blame client, except that Put client doesn't care.
			return
		}
		s.Put(a.Uid, a.Pk, a.Ver)
		*reply = nil
	}
	h[HistoryRpc] = func(arg []byte, reply *[]byte) {
		a, _, err := HistoryArgDecode(arg)
		if err {
			r := &HistoryReply{Err: true}
			*reply = HistoryReplyEncode(*reply, r)
			return
		}
		r0, r1, r2, r3, r4 := s.History(a.Uid, a.PrevEpoch, a.PrevVerLen)
		r := &HistoryReply{ChainProof: r0, LinkSig: r1, Hist: r2, Bound: r3, Err: r4}
		*reply = HistoryReplyEncode(*reply, r)
	}
	h[AuditRpc] = func(arg []byte, reply *[]byte) {
		a, _, err := AuditArgDecode(arg)
		if err {
			r := &AuditReply{Err: true}
			*reply = AuditReplyEncode(*reply, r)
			return
		}
		r0, r1 := s.Audit(a.PrevEpoch)
		r := &AuditReply{P: r0, Err: r1}
		*reply = AuditReplyEncode(*reply, r)
	}
	return advrpc.NewServer(h)
}

func CallStart(c *advrpc.Client) (chain *StartChain, vrf *StartVrf, err ktcore.Blame) {
	rb := new([]byte)
	if c.Call(StartRpc, nil, rb) {
		err = ktcore.BlameUnknown
		return
	}
	r, _, errb := StartReplyDecode(*rb)
	chain = r.Chain
	vrf = r.Vrf
	if errb {
		err = ktcore.BlameServ
		return
	}
	return
}

func CallPut(c *advrpc.Client, uid uint64, pk []byte, ver uint64) {
	a := &PutArg{Uid: uid, Pk: pk, Ver: ver}
	ab := PutArgEncode(nil, a)
	rb := new([]byte)
	// don't bubble up Put errs bc caller doesn't care to know.
	c.Call(PutRpc, ab, rb)
}

func CallHistory(c *advrpc.Client, uid, prevEpoch, prevVerLen uint64) (chainProof []byte, linkSig []byte, hist []*ktcore.Memb, bound *ktcore.NonMemb, err ktcore.Blame) {
	a := &HistoryArg{Uid: uid, PrevEpoch: prevEpoch, PrevVerLen: prevVerLen}
	ab := HistoryArgEncode(nil, a)
	rb := new([]byte)
	if c.Call(HistoryRpc, ab, rb) {
		err = ktcore.BlameUnknown
		return
	}
	r, _, errb := HistoryReplyDecode(*rb)
	if errb {
		err = ktcore.BlameServ
		return
	}
	if r.Err {
		err = ktcore.BlameServ
		return
	}
	return r.ChainProof, r.LinkSig, r.Hist, r.Bound, ktcore.BlameNone
}

func CallAudit(c *advrpc.Client, prevEpoch uint64) (p []*ktcore.AuditProof, err ktcore.Blame) {
	a := &AuditArg{PrevEpoch: prevEpoch}
	ab := AuditArgEncode(nil, a)
	rb := new([]byte)
	if c.Call(AuditRpc, ab, rb) {
		err = ktcore.BlameUnknown
		return
	}
	r, _, errb := AuditReplyDecode(*rb)
	if errb {
		err = ktcore.BlameServ
		return
	}
	if r.Err {
		err = ktcore.BlameServ
		return
	}
	return r.P, ktcore.BlameNone
}
