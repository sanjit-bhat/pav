package kt

import (
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/secure-chat/kt/kt_shim"
	"github.com/mit-pdos/secure-chat/kt/shared"
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

func (ks *keyServ) put(entry *shared.UnameKey) *shared.KeyLog {
	ks.mu.Lock()
	ks.log.Append(entry)
	outLog := ks.log.DeepCopy()
	ks.mu.Unlock()
	return outLog
}

func (ks *keyServ) get() *shared.KeyLog {
	ks.mu.Lock()
	outLog := ks.log.DeepCopy()
	ks.mu.Unlock()
	return outLog
}

func (ks *keyServ) start(me grove_ffi.Address) {
	handlers := make(map[uint64]func([]byte, *[]byte))

	handlers[shared.RpcKeyServ_Put] =
		func(enc_args []byte, enc_reply *[]byte) {
			entry := new(shared.UnameKey)
			_, err := entry.Decode(enc_args)
			if err != shared.ErrNone {
				return
			}
			*enc_reply = ks.put(entry).Encode()
		}

	handlers[shared.RpcKeyServ_Get] =
		func(enc_args []byte, enc_reply *[]byte) {
			*enc_reply = ks.get().Encode()
		}

	urpc.MakeServer(handlers).Serve(me)
}

// Shared checks.

func injestNewLog(currLog *shared.KeyLog, newLogB []byte) (*shared.KeyLog, shared.ErrorT) {
	newLog := new(shared.KeyLog)
	_, err1 := newLog.Decode(newLogB)
	if err1 != shared.ErrNone {
		return nil, err1
	}

	if !currLog.IsPrefix(newLog) {
		return nil, shared.ErrInjestNewLog_Prefix
	}
	return newLog, shared.ErrNone
}

// Auditor.

type auditor struct {
	mu  *sync.Mutex
	log *shared.KeyLog
	sk  *kt_shim.SignerT
}

func newAuditor(sk *kt_shim.SignerT) *auditor {
	l := shared.NewKeyLog()
	return &auditor{mu: new(sync.Mutex), log: l, sk: sk}
}

func (a *auditor) update(newLogB []byte) shared.ErrorT {
	a.mu.Lock()
	newLog, err1 := injestNewLog(a.log, newLogB)
	if err1 != shared.ErrNone {
		a.mu.Unlock()
		return err1
	}

	a.log = newLog
	a.mu.Unlock()
	return shared.ErrNone
}

func (a *auditor) get() *shared.SigLog {
	a.mu.Lock()
	logCopy := a.log.DeepCopy()
	logB := logCopy.Encode()
	sig := a.sk.Sign(logB)
	a.mu.Unlock()
	return &shared.SigLog{Sig: sig, Log: logCopy}
}

func (a *auditor) start(me grove_ffi.Address) {
	handlers := make(map[uint64]func([]byte, *[]byte))

	handlers[shared.RpcAdtr_Update] =
		func(enc_args []byte, enc_reply *[]byte) {
			err := a.update(enc_args)
			machine.Assume(err == shared.ErrNone)
		}

	handlers[shared.RpcAdtr_Get] =
		func(enc_args []byte, enc_reply *[]byte) {
			*enc_reply = a.get().Encode()
		}

	urpc.MakeServer(handlers).Serve(me)
}

// Key client.

type keyCli struct {
	log     *shared.KeyLog
	serv    *urpc.Client
	adtrs   []*urpc.Client
	adtrVks []*kt_shim.VerifierT
}

func newKeyCli(serv grove_ffi.Address, adtrs []grove_ffi.Address, adtrVks []*kt_shim.VerifierT) *keyCli {
	l := shared.NewKeyLog()
	servC := urpc.MakeClient(serv)
	adtrsC := make([]*urpc.Client, len(adtrs))
	for i, addr := range adtrs {
		adtrsC[i] = urpc.MakeClient(addr)
	}
	return &keyCli{log: l, serv: servC, adtrs: adtrsC, adtrVks: adtrVks}
}

func (kc *keyCli) register(entry *shared.UnameKey) (uint64, shared.ErrorT) {
	entryB := entry.Encode()
	newLogB := make([]byte, 0)
	err1 := kc.serv.Call(shared.RpcKeyServ_Put, entryB, &newLogB, 100)
	machine.Assume(err1 == urpc.ErrNone)

	newLog, err2 := injestNewLog(kc.log, newLogB)
	if err2 != shared.ErrNone {
		return 0, err2
	}
	epoch, key, ok := newLog.Lookup(entry.Uname)
	if !ok || !shared.BytesEqual(key, entry.Key) {
		return 0, shared.ErrKeyCli_RegNoExist
	}

	kc.log = newLog
	return epoch, shared.ErrNone
}

func (kc *keyCli) lookup(uname uint64) (uint64, []byte, shared.ErrorT) {
	newLogB := make([]byte, 0)
	err1 := kc.serv.Call(shared.RpcKeyServ_Get, nil, &newLogB, 100)
	machine.Assume(err1 == urpc.ErrNone)

	newLog, err2 := injestNewLog(kc.log, newLogB)
	if err2 != shared.ErrNone {
		return 0, nil, err2
	}
	epoch, key, ok := newLog.Lookup(uname)
	if !ok {
		return 0, nil, shared.ErrKeyCli_LookNoExist
	}

	kc.log = newLog
	return epoch, key, shared.ErrNone
}

func (kc *keyCli) audit(adtrId uint64) (uint64, shared.ErrorT) {
	adtrSigB := make([]byte, 0)
	err1 := kc.adtrs[adtrId].Call(shared.RpcAdtr_Get, nil, &adtrSigB, 100)
	machine.Assume(err1 == urpc.ErrNone)

	adtrSig := new(shared.SigLog)
	_, err2 := adtrSig.Decode(adtrSigB)
	if err2 != shared.ErrNone {
		return 0, err2
	}

	adtrLogB := adtrSig.Log.Encode()
	err3 := kc.adtrVks[adtrId].Verify(adtrSig.Sig, adtrLogB)
	if err3 != shared.ErrNone {
		return 0, err3
	}
	adtrLog := adtrSig.Log

	if kc.log.IsPrefix(adtrLog) {
		return kc.log.Len(), shared.ErrNone
	}
	if adtrLog.IsPrefix(kc.log) {
		return adtrLog.Len(), shared.ErrNone
	}

	return 0, shared.ErrKeyCli_AuditPrefix
}

// Tests.

// Two clients lookup the same uname, talk to some auditor servers
// (at least one honest), and assert that their returned keys are the same.
func testAuditPass(servAddr grove_ffi.Address, adtrAddrs []grove_ffi.Address) {
	// Start the server.
	go func() {
		s := newKeyServ()
		s.start(servAddr)
	}()
	machine.Sleep(1_000_000)

	// Make auditor keys.
	badSk0, badVk0 := kt_shim.MakeKeys()
	goodSk0, goodVk0 := kt_shim.MakeKeys()
	badSk1, badVk1 := kt_shim.MakeKeys()
	var adtrVks []*kt_shim.VerifierT
	adtrVks = append(adtrVks, badVk0)
	adtrVks = append(adtrVks, goodVk0)
	adtrVks = append(adtrVks, badVk1)

	// Start the auditors.
	go func() {
		a := newAuditor(badSk0)
		a.start(adtrAddrs[0])
	}()
	go func() {
		a := newAuditor(goodSk0)
		a.start(adtrAddrs[1])
	}()
	go func() {
		a := newAuditor(badSk1)
		a.start(adtrAddrs[2])
	}()
	machine.Sleep(1_000_000)

	// Start the clients.
	cReg := newKeyCli(servAddr, adtrAddrs, adtrVks)
	cLook0 := newKeyCli(servAddr, adtrAddrs, adtrVks)
	cLook1 := newKeyCli(servAddr, adtrAddrs, adtrVks)

	// Register a key.
	uname0 := uint64(42)
	key0 := []byte("key0")
	goodEntry := &shared.UnameKey{Uname: uname0, Key: key0}
	_, err0 := cReg.register(goodEntry)
	machine.Assume(err0 == shared.ErrNone)

	// Lookup that uname.
	epoch0, retKey0, err1 := cLook0.lookup(uname0)
	machine.Assume(err1 == shared.ErrNone)
	epoch1, retKey1, err2 := cLook1.lookup(uname0)
	machine.Assume(err2 == shared.ErrNone)

	// Start the auditors.
	badAdtr0 := urpc.MakeClient(adtrAddrs[0])
	goodAdtr0 := urpc.MakeClient(adtrAddrs[1])
	badAdtr1 := urpc.MakeClient(adtrAddrs[2])

	// Update the bad auditors.
	uname1 := uint64(43)
	key1 := []byte("key1")
	badEntry := &shared.UnameKey{Uname: uname1, Key: key1}
	badLog := shared.NewKeyLog()
	badLog.Append(badEntry)
	badLogB := badLog.Encode()
	emptyB := make([]byte, 0)
	err3 := badAdtr0.Call(shared.RpcAdtr_Update, badLogB, &emptyB, 100)
	machine.Assume(err3 == urpc.ErrNone)
	err4 := badAdtr1.Call(shared.RpcAdtr_Update, badLogB, &emptyB, 100)
	machine.Assume(err4 == urpc.ErrNone)

	// Update the good auditor.
	goodLog := shared.NewKeyLog()
	goodLog.Append(goodEntry)
	goodLogB := goodLog.Encode()
	err5 := goodAdtr0.Call(shared.RpcAdtr_Update, goodLogB, &emptyB, 100)
	machine.Assume(err5 == urpc.ErrNone)

	// Contact auditors.
	// A dishonest auditor can give us anything, we don't trust it.
	// But we call it here to show we can handle its output without panic'ing.
	_, _ = cLook0.audit(0)
	auditEpoch0, err6 := cLook0.audit(1)
	// Could do a more fine-grained check like
	// "if the sig passed, assert no other err".
	machine.Assume(err6 == shared.ErrNone)

	_, _ = cLook1.audit(2)
	auditEpoch1, err7 := cLook1.audit(1)
	machine.Assume(err7 == shared.ErrNone)

	// Big assert.
	if epoch0 == epoch1 && epoch0 <= auditEpoch0 && epoch1 <= auditEpoch1 {
		machine.Assert(shared.BytesEqual(retKey0, retKey1))
	}
}

// An auditor sees writes from a server. A user's lookup goes to
// a different server, but the user later contacts the auditor.
// The user's audit should return an error.
func testAuditFail(servAddr1, servAddr2, adtrAddr grove_ffi.Address) {
	go func() {
		s := newKeyServ()
		s.start(servAddr1)
	}()
	go func() {
		s := newKeyServ()
		s.start(servAddr2)
	}()
	machine.Sleep(1_000_000)

	adtrSigner, adtrVerifier := kt_shim.MakeKeys()
	go func() {
		a := newAuditor(adtrSigner)
		a.start(adtrAddr)
	}()
	machine.Sleep(1_000_000)

	var adtrs []grove_ffi.Address
	adtrs = append(adtrs, adtrAddr)
	var adtrVks []*kt_shim.VerifierT
	adtrVks = append(adtrVks, adtrVerifier)
	cReg1 := newKeyCli(servAddr1, adtrs, adtrVks)
	cReg2 := newKeyCli(servAddr2, adtrs, adtrVks)
	cLook2 := newKeyCli(servAddr2, adtrs, adtrVks)

	aliceUname := uint64(42)
	aliceKey1 := []byte("pubkey1")
	aliceKey2 := []byte("pubkey2")
	uk1 := &shared.UnameKey{Uname: aliceUname, Key: aliceKey1}
	uk2 := &shared.UnameKey{Uname: aliceUname, Key: aliceKey2}
	_, err1 := cReg1.register(uk1)
	machine.Assume(err1 == shared.ErrNone)
	_, err2 := cReg2.register(uk2)
	machine.Assume(err2 == shared.ErrNone)

	adtrCli := urpc.MakeClient(adtrAddr)
	goodLog := shared.NewKeyLog()
	goodLog.Append(uk1)
	goodLogB := goodLog.Encode()
	emptyB := make([]byte, 0)
	err3 := adtrCli.Call(shared.RpcAdtr_Update, goodLogB, &emptyB, 100)
	machine.Assume(err3 == urpc.ErrNone)

	_, _, err4 := cLook2.lookup(aliceUname)
	machine.Assume(err4 == shared.ErrNone)

	_, err5 := cLook2.audit(0)
	machine.Assert(err5 == shared.ErrKeyCli_AuditPrefix)
}
