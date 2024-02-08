package kt

import (
	"bytes"
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/secure-chat/kt/shared"
	"github.com/tchajed/goose/machine"
	"sync"
)

// Key server.

type KeyServ struct {
	log *shared.KeyLog
	mu  *sync.Mutex
}

func NewKeyServ() *KeyServ {
	return &KeyServ{log: shared.NewKeyLog(), mu: new(sync.Mutex)}
}

func (ks *KeyServ) appendLog(entry *shared.UnameKey) *shared.KeyLog {
	ks.mu.Lock()
	ks.log.Append(entry)
	outLog := ks.log.DeepCopy()
	ks.mu.Unlock()
	return outLog
}

func (ks *KeyServ) getLog() *shared.KeyLog {
	ks.mu.Lock()
	outLog := ks.log.DeepCopy()
	ks.mu.Unlock()
	return outLog
}

func (ks *KeyServ) Start(me grove_ffi.Address) {
	handlers := make(map[uint64]func([]byte, *[]byte))

	handlers[shared.RpcAppendLog] =
		func(enc_args []byte, enc_reply *[]byte) {
			entry := new(shared.UnameKey)
			if _, err := entry.Decode(enc_args); err != shared.ErrNone {
				return
			}
			*enc_reply = ks.appendLog(entry).Encode()
		}

	handlers[shared.RpcGetLog] =
		func(enc_args []byte, enc_reply *[]byte) {
			*enc_reply = ks.getLog().Encode()
		}

	urpc.MakeServer(handlers).Serve(me)
}

// Shared checks.

type checkLogIn struct {
	currLog  *shared.KeyLog
	newLogB  []byte
	uname    uint64
	doLookup bool
}

type checkLogOut struct {
	newLog *shared.KeyLog
	epoch  uint64
	key    []byte
	err    shared.ErrorT
}

func errNewLogOut(err shared.ErrorT) *checkLogOut {
	return &checkLogOut{newLog: nil, epoch: 0, key: nil, err: err}
}

// Decode RPC ret, check log prefix, check key lookup.
func checkLog(in *checkLogIn) *checkLogOut {
	newLog := new(shared.KeyLog)
	_, err1 := newLog.Decode(in.newLogB)
	if err1 != shared.ErrNone {
		return errNewLogOut(err1)
	}

	if !in.currLog.IsPrefix(newLog) {
		return errNewLogOut(shared.ErrKeyCli_CheckLogPrefix)
	}

	if !in.doLookup {
		return &checkLogOut{newLog: newLog, epoch: 0, key: nil, err: shared.ErrNone}
	}

	epoch, key, ok := in.currLog.Lookup(in.uname)
	if !ok {
		return errNewLogOut(shared.ErrKeyCli_CheckLogLookup)
	}
	return &checkLogOut{newLog: newLog, epoch: epoch, key: key, err: shared.ErrNone}
}

// Auditor.

type auditor struct {
	log  *shared.KeyLog
	serv *urpc.Client
	mu   *sync.Mutex
}

func newAuditor(servAddr grove_ffi.Address) *auditor {
	l := shared.NewKeyLog()
	c := urpc.MakeClient(servAddr)
	return &auditor{log: l, serv: c, mu: new(sync.Mutex)}
}

func (a *auditor) doAudit() shared.ErrorT {
	a.mu.Lock()
	newLogB := make([]byte, 0)
	err1 := a.serv.Call(shared.RpcGetLog, nil, &newLogB, 100)
	machine.Assume(err1 == urpc.ErrNone)

	in := &checkLogIn{currLog: a.log, newLogB: newLogB, uname: 0, doLookup: false}
	out := checkLog(in)
	if out.err != shared.ErrNone {
		a.mu.Unlock()
		return out.err
	}

	a.log = out.newLog
	a.mu.Unlock()
	return shared.ErrNone
}

func (a *auditor) getAudit() *shared.KeyLog {
	a.mu.Lock()
	logCopy := a.log.DeepCopy()
	a.mu.Unlock()
	return logCopy
}

// Key client.

type keyCli struct {
	log   *shared.KeyLog
	serv  *urpc.Client
	adtrs []*auditor
}

func newKeyCli(host grove_ffi.Address, adtrs []*auditor) *keyCli {
	l := shared.NewKeyLog()
	c := urpc.MakeClient(host)
	return &keyCli{log: l, serv: c, adtrs: adtrs}
}

func (kc *keyCli) register(entry *shared.UnameKey) (uint64, shared.ErrorT) {
	entryB := entry.Encode()
	newLogB := make([]byte, 0)
	err1 := kc.serv.Call(shared.RpcAppendLog, entryB, &newLogB, 100)
	machine.Assume(err1 == urpc.ErrNone)

	in := &checkLogIn{currLog: kc.log, newLogB: newLogB, uname: entry.Uname, doLookup: true}
	out := checkLog(in)
	if out.err != shared.ErrNone {
		return 0, out.err
	}
	if out.epoch < uint64(in.currLog.Len()) {
		return 0, shared.ErrKeyCli_RegNoExist
	}
	kc.log = out.newLog
	return out.epoch, shared.ErrNone
}

func (kc *keyCli) lookup(uname uint64) (uint64, []byte, shared.ErrorT) {
	newLogB := make([]byte, 0)
	err1 := kc.serv.Call(shared.RpcGetLog, nil, &newLogB, 100)
	machine.Assume(err1 == urpc.ErrNone)

	in := &checkLogIn{currLog: kc.log, newLogB: newLogB, uname: uname, doLookup: true}
	out := checkLog(in)
	if out.err != shared.ErrNone {
		return 0, nil, out.err
	}
	kc.log = out.newLog
	return out.epoch, out.key, shared.ErrNone
}

func (kc *keyCli) audit(aId uint64) (uint64, shared.ErrorT) {
	audLog := kc.adtrs[aId].getAudit()
	if !kc.log.IsPrefix(audLog) {
		return 0, shared.ErrKeyCli_AuditPrefix
	}
	kc.log = audLog
	return uint64(kc.log.Len()), shared.ErrNone
}

// Tests.

// Two clients lookup the same uname, talk to the same honest auditor,
// and assert that their returned keys are the same.
func testAuditPass(servAddr grove_ffi.Address) {
	aud := newAuditor(servAddr)
	adtrs := []*auditor{aud}
	cReg := newKeyCli(servAddr, adtrs)
	cLook1 := newKeyCli(servAddr, adtrs)
	cLook2 := newKeyCli(servAddr, adtrs)

	aliceUname := uint64(42)
	aliceKey := []byte("pubkey")
	uk := &shared.UnameKey{Uname: aliceUname, Key: aliceKey}
	_, err1 := cReg.register(uk)
	machine.Assume(err1 == shared.ErrNone)

	err2 := aud.doAudit()
	machine.Assume(err2 == shared.ErrNone)

	epochL1, retKey1, err := cLook1.lookup(aliceUname)
	machine.Assume(err == shared.ErrNone)
	epochL2, retKey2, err := cLook2.lookup(aliceUname)
	machine.Assume(err == shared.ErrNone)

	_, err = cLook1.audit(0)
	machine.Assume(err == shared.ErrNone)
	_, err = cLook2.audit(0)
	machine.Assume(err == shared.ErrNone)
	// Don't need to check audit epoch since we know it needs to cover epochs
	// we've already seen.

	if epochL1 == epochL2 {
		machine.Assert(bytes.Equal(retKey1, retKey2))
	}
}

// An auditor sees writes from a server. A user's lookup goes to
// a different server, but the user later contacts the auditor.
// The user's audit should return an error.
func testAuditFail(servAddrs []grove_ffi.Address) {
	aud := newAuditor(servAddrs[0])
	adtrs := []*auditor{aud}
	cReg1 := newKeyCli(servAddrs[0], adtrs)
	cReg2 := newKeyCli(servAddrs[1], adtrs)
	cLook2 := newKeyCli(servAddrs[1], adtrs)

	aliceUname := uint64(42)
	aliceKey1 := []byte("pubkey1")
	aliceKey2 := []byte("pubkey2")
	uk1 := &shared.UnameKey{Uname: aliceUname, Key: aliceKey1}
	uk2 := &shared.UnameKey{Uname: aliceUname, Key: aliceKey2}
	var err shared.ErrorT
	_, err = cReg1.register(uk1)
	machine.Assume(err == shared.ErrNone)
	_, err = cReg2.register(uk2)
	machine.Assume(err == shared.ErrNone)

	err1 := aud.doAudit()
	machine.Assume(err1 == shared.ErrNone)

	_, _, err = cLook2.lookup(aliceUname)
	machine.Assume(err == shared.ErrNone)

	_, err = cLook2.audit(0)
	machine.Assert(err == shared.ErrKeyCli_AuditPrefix)
}
