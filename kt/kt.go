package kt

import (
	"bytes"
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/secure-chat/kt/shared"
	kt_ffi "github.com/mit-pdos/secure-chat/kt/shim"
	"github.com/tchajed/goose/machine"
	"sync"
)

// Key server.

type keyServ struct {
	mu  *sync.Mutex
	log *shared.KeyLog
}

func newKeyServ() *keyServ {
	return &keyServ{mu: new(sync.Mutex), log: shared.NewKeyLog()}
}

func (ks *keyServ) appendLog(entry *shared.UnameKey) *shared.KeyLog {
	ks.mu.Lock()
	ks.log.Append(entry)
	outLog := ks.log.DeepCopy()
	ks.mu.Unlock()
	return outLog
}

func (ks *keyServ) getLog() *shared.KeyLog {
	ks.mu.Lock()
	outLog := ks.log.DeepCopy()
	ks.mu.Unlock()
	return outLog
}

func (ks *keyServ) start(me grove_ffi.Address) {
	handlers := make(map[uint64]func([]byte, *[]byte))

	handlers[shared.RpcAppendLog] =
		func(enc_args []byte, enc_reply *[]byte) {
			entry := new(shared.UnameKey)
			_, err := entry.Decode(enc_args)
			if err != shared.ErrNone {
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

	epoch, key, ok := newLog.Lookup(in.uname)
	if !ok {
		return errNewLogOut(shared.ErrKeyCli_CheckLogLookup)
	}
	return &checkLogOut{newLog: newLog, epoch: epoch, key: key, err: shared.ErrNone}
}

// Auditor.

type auditor struct {
	mu   *sync.Mutex
	log  *shared.KeyLog
	serv *urpc.Client
	key  *kt_ffi.SignerT
}

func newAuditor(servAddr grove_ffi.Address, key *kt_ffi.SignerT) *auditor {
	l := shared.NewKeyLog()
	c := urpc.MakeClient(servAddr)
	return &auditor{mu: new(sync.Mutex), log: l, serv: c, key: key}
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

func (a *auditor) getAudit() *shared.SigLog {
	a.mu.Lock()
	logCopy := a.log.DeepCopy()
	logB := logCopy.Encode()
	sig := a.key.Sign(logB)
	a.mu.Unlock()
	return shared.NewSigLog(sig, logCopy)
}

func (a *auditor) start(me grove_ffi.Address) {
	handlers := make(map[uint64]func([]byte, *[]byte))

	handlers[shared.RpcDoAudit] =
		func(enc_args []byte, enc_reply *[]byte) {
			err := a.doAudit()
			machine.Assume(err == shared.ErrNone)
		}

	handlers[shared.RpcGetAudit] =
		func(enc_args []byte, enc_reply *[]byte) {
			*enc_reply = a.getAudit().Encode()
		}

	urpc.MakeServer(handlers).Serve(me)
}

// Key client.

type keyCli struct {
	log      *shared.KeyLog
	serv     *urpc.Client
	adtrs    []*urpc.Client
	adtrKeys []*kt_ffi.VerifierT
}

func newKeyCli(serv grove_ffi.Address, adtrs []grove_ffi.Address, adtrKeys []*kt_ffi.VerifierT) *keyCli {
	l := shared.NewKeyLog()
	servC := urpc.MakeClient(serv)
	adtrsC := make([]*urpc.Client, len(adtrs))
	for i, addr := range adtrs {
		adtrsC[i] = urpc.MakeClient(addr)
	}
	return &keyCli{log: l, serv: servC, adtrs: adtrsC, adtrKeys: adtrKeys}
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
	if out.epoch < in.currLog.Len() {
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
	sigLogB := make([]byte, 0)
	err1 := kc.adtrs[aId].Call(shared.RpcGetAudit, nil, &sigLogB, 100)
	machine.Assume(err1 == urpc.ErrNone)

	sigLog := new(shared.SigLog)
	_, err2 := sigLog.Decode(sigLogB)
	if err2 != shared.ErrNone {
		return 0, err2
	}

	logB := sigLog.Log.Encode()
	err3 := kc.adtrKeys[aId].Verify(sigLog.Sig, logB)
	if err3 != shared.ErrNone {
		return 0, err3
	}

	if !kc.log.IsPrefix(sigLog.Log) {
		return 0, shared.ErrKeyCli_AuditPrefix
	}
	kc.log = sigLog.Log

	return kc.log.Len(), shared.ErrNone
}

// Tests.

// Two clients lookup the same uname, talk to the same honest auditor,
// and assert that their returned keys are the same.
func testAuditPass() {
	servAddr := grove_ffi.MakeAddress("0.0.0.0:6060")
	go func() {
		s := newKeyServ()
		s.start(servAddr)
	}()
	machine.Sleep(1_000_000)

	audSigner, audVerifier := kt_ffi.MakeKeys()
	audAddr := grove_ffi.MakeAddress("0.0.0.0:6061")
	go func() {
		a := newAuditor(servAddr, audSigner)
		a.start(audAddr)
	}()
	machine.Sleep(1_000_000)

	adtrs := []grove_ffi.Address{audAddr}
	adtrKeys := []*kt_ffi.VerifierT{audVerifier}
	cReg := newKeyCli(servAddr, adtrs, adtrKeys)
	cLook1 := newKeyCli(servAddr, adtrs, adtrKeys)
	cLook2 := newKeyCli(servAddr, adtrs, adtrKeys)

	aliceUname := uint64(42)
	aliceKey := []byte("pubkey")
	uk := &shared.UnameKey{Uname: aliceUname, Key: aliceKey}
	_, err1 := cReg.register(uk)
	machine.Assume(err1 == shared.ErrNone)

	audC := urpc.MakeClient(audAddr)
	emptyB := make([]byte, 0)
	err2 := audC.Call(shared.RpcDoAudit, nil, &emptyB, 100)
	machine.Assume(err2 == urpc.ErrNone)

	epochL1, retKey1, err := cLook1.lookup(aliceUname)
	machine.Assume(err == shared.ErrNone)
	epochL2, retKey2, err := cLook2.lookup(aliceUname)
	machine.Assume(err == shared.ErrNone)

	_, err3 := cLook1.audit(0)
	machine.Assume(err3 == shared.ErrNone)
	_, err4 := cLook2.audit(0)
	machine.Assume(err4 == shared.ErrNone)
	// Don't need to check audit epoch since we know it needs to cover epochs
	// we've already seen.

	if epochL1 == epochL2 {
		machine.Assert(bytes.Equal(retKey1, retKey2))
	}
}

// An auditor sees writes from a server. A user's lookup goes to
// a different server, but the user later contacts the auditor.
// The user's audit should return an error.
func testAuditFail() {
	servAddr1 := grove_ffi.MakeAddress("0.0.0.0:6060")
	servAddr2 := grove_ffi.MakeAddress("0.0.0.0:6061")
	go func() {
		s := newKeyServ()
		s.start(servAddr1)
	}()
	go func() {
		s := newKeyServ()
		s.start(servAddr2)
	}()
	machine.Sleep(1_000_000)

	audSigner, audVerifier := kt_ffi.MakeKeys()
	audAddr := grove_ffi.MakeAddress("0.0.0.0:6062")
	go func() {
		a := newAuditor(servAddr1, audSigner)
		a.start(audAddr)
	}()
	machine.Sleep(1_000_000)

	adtrs := []grove_ffi.Address{audAddr}
	adtrKeys := []*kt_ffi.VerifierT{audVerifier}
	cReg1 := newKeyCli(servAddr1, adtrs, adtrKeys)
	cReg2 := newKeyCli(servAddr2, adtrs, adtrKeys)
	cLook2 := newKeyCli(servAddr2, adtrs, adtrKeys)

	aliceUname := uint64(42)
	aliceKey1 := []byte("pubkey1")
	aliceKey2 := []byte("pubkey2")
	uk1 := &shared.UnameKey{Uname: aliceUname, Key: aliceKey1}
	uk2 := &shared.UnameKey{Uname: aliceUname, Key: aliceKey2}
	_, err1 := cReg1.register(uk1)
	machine.Assume(err1 == shared.ErrNone)
	_, err2 := cReg2.register(uk2)
	machine.Assume(err2 == shared.ErrNone)

	audC := urpc.MakeClient(audAddr)
	emptyB := make([]byte, 0)
	err3 := audC.Call(shared.RpcDoAudit, nil, &emptyB, 100)
	machine.Assume(err3 == urpc.ErrNone)

	_, _, err4 := cLook2.lookup(aliceUname)
	machine.Assume(err4 == shared.ErrNone)

	_, err5 := cLook2.audit(0)
	machine.Assert(err5 == shared.ErrKeyCli_AuditPrefix)
}
