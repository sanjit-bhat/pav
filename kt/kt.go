package kt

import (
	"bytes"
	"github.com/mit-pdos/secure-chat/kt/shared"
	"github.com/tchajed/goose/machine"
	"sync"
)

// Common data structures.

type unameKey struct {
	uname uint64
	key   []byte
}

func (uk *unameKey) deepCopy() *unameKey {
	newKey := make([]byte, len(uk.key))
	copy(newKey, uk.key)
	return &unameKey{uname: uk.uname, key: newKey}
}

func (uk1 *unameKey) isEqual(uk2 *unameKey) bool {
	return uk1.uname == uk2.uname && bytes.Equal(uk1.key, uk2.key)
}

type keyLog struct {
	log []*unameKey
}

func newKeyLog() *keyLog {
	return &keyLog{log: make([]*unameKey, 0)}
}

func (l *keyLog) deepCopy() *keyLog {
	newLog := make([]*unameKey, 0, len(l.log))
	for _, entry := range l.log {
		newLog = append(newLog, entry.deepCopy())
	}
	return &keyLog{log: newLog}
}

func (small *keyLog) isPrefix(big *keyLog) bool {
	if len(big.log) < len(small.log) {
		return false
	}
	ans := true
	for i := 0; i < len(small.log); i++ {
		if !small.log[i].isEqual(big.log[i]) {
			ans = false
		}
	}
	return ans
}

func (l *keyLog) lookup(uname uint64) ([]byte, bool) {
	ok := false
	var key []byte
	for i := len(l.log) - 1; i >= 0; i-- {
		if !ok && l.log[i].uname == uname {
			ok = true
			key = l.log[i].key
		}
	}
	return key, ok
}

// Key server.

type keyServ struct {
	log *keyLog
	mu  *sync.Mutex
}

func newKeyServ() *keyServ {
	return &keyServ{log: newKeyLog(), mu: new(sync.Mutex)}
}

func (ks *keyServ) appendLog(entry *unameKey) *keyLog {
	ks.mu.Lock()
	ks.log.log = append(ks.log.log, entry)
	outLog := ks.log.deepCopy()
	ks.mu.Unlock()
	return outLog
}

func (ks *keyServ) getLog() *keyLog {
	ks.mu.Lock()
	outLog := ks.log.deepCopy()
	ks.mu.Unlock()
	return outLog
}

// Auditor.

type auditor struct {
	log *keyLog
	mu  *sync.Mutex
}

func newAuditor() *auditor {
	return &auditor{log: newKeyLog(), mu: new(sync.Mutex)}
}

func (a *auditor) doAudit(newLog *keyLog) shared.ErrorT {
	a.mu.Lock()
	if !a.log.isPrefix(newLog) {
		a.mu.Unlock()
		return shared.ErrAudDoPrefix
	} else {
		a.log = newLog
		a.mu.Unlock()
		return shared.ErrNone
	}
}

func (a *auditor) getAudit() *keyLog {
	a.mu.Lock()
	logCopy := a.log.deepCopy()
	a.mu.Unlock()
	return logCopy
}

// Key client.

type keyCli struct {
	log   *keyLog
	serv  *keyServ
	adtrs []*auditor
}

func newKeyCli(serv *keyServ, adtrs []*auditor) *keyCli {
	return &keyCli{log: newKeyLog(), serv: serv, adtrs: adtrs}
}

func (kc *keyCli) register(entry *unameKey) shared.ErrorT {
	newLog := kc.serv.appendLog(entry)
	if !kc.log.isPrefix(newLog) {
		return shared.ErrKeyCliRegPrefix
	}
	kc.log = newLog
	return shared.ErrNone
}

func (kc *keyCli) lookup(uname uint64) ([]byte, shared.ErrorT) {
	newLog := kc.serv.getLog()
	if !kc.log.isPrefix(newLog) {
		return nil, shared.ErrKeyCliLookupPrefix
	}
	kc.log = newLog
	key, ok := kc.log.lookup(uname)
	if !ok {
		return nil, shared.ErrKeyCliNoKey
	}
	return key, shared.ErrNone
}

func (kc *keyCli) audit(aId uint64) shared.ErrorT {
	audLog := kc.adtrs[aId].getAudit()
	// TODO: design decision isPrefix/isEqual and whether to store log for later.
	if !kc.log.isPrefix(audLog) {
		return shared.ErrKeyCliAuditPrefix
	}
	kc.log = audLog
	return shared.ErrNone
}

// Tests.

func testAuditPass() {
	kserv := newKeyServ()
	aud := newAuditor()
	adtrs := []*auditor{aud}
	cReg := newKeyCli(kserv, adtrs)
	cLook1 := newKeyCli(kserv, adtrs)
	cLook2 := newKeyCli(kserv, adtrs)

	aliceUname := uint64(42)
	aliceKey := []byte("pubkey")
	uk := &unameKey{uname: aliceUname, key: aliceKey}
	var err shared.ErrorT
	err = cReg.register(uk)
	machine.Assume(err == shared.ErrNone)

	newLog := kserv.getLog()
	err = aud.doAudit(newLog)
	machine.Assume(err == shared.ErrNone)

	retKey1, err := cLook1.lookup(aliceUname)
	machine.Assume(err == shared.ErrNone)
	retKey2, err := cLook2.lookup(aliceUname)
	machine.Assume(err == shared.ErrNone)

	err = cLook1.audit(0)
	machine.Assume(err == shared.ErrNone)
	err = cLook2.audit(0)
	machine.Assume(err == shared.ErrNone)

	machine.Assert(bytes.Equal(retKey1, retKey2))
}

func testAuditFail() {
	aud1 := newAuditor()
	aud2 := newAuditor()
	adtrs := []*auditor{aud1, aud2}

	kserv1 := newKeyServ()
	cReg1 := newKeyCli(kserv1, adtrs)
	cLook1 := newKeyCli(kserv1, adtrs)

	kserv2 := newKeyServ()
	cReg2 := newKeyCli(kserv2, adtrs)
	cLook2 := newKeyCli(kserv2, adtrs)

	aliceUname := uint64(42)
	aliceKey1 := []byte("pubkey1")
	aliceKey2 := []byte("pubkey2")
	uk1 := &unameKey{uname: aliceUname, key: aliceKey1}
	uk2 := &unameKey{uname: aliceUname, key: aliceKey2}
	var err shared.ErrorT
	err = cReg1.register(uk1)
	machine.Assume(err == shared.ErrNone)
	err = cReg2.register(uk2)
	machine.Assume(err == shared.ErrNone)

	newLog1 := kserv1.getLog()
	err = aud1.doAudit(newLog1)
	machine.Assume(err == shared.ErrNone)
	newLog2 := kserv2.getLog()
	err = aud2.doAudit(newLog2)
	machine.Assume(err == shared.ErrNone)

	retKey1, err := cLook1.lookup(aliceUname)
	machine.Assume(err == shared.ErrNone)
	retKey2, err := cLook2.lookup(aliceUname)
	machine.Assume(err == shared.ErrNone)

	err = cLook1.audit(0)
	machine.Assume(err == shared.ErrNone)
	err = cLook2.audit(0)
	machine.Assert(err == shared.ErrKeyCliAuditPrefix)

	machine.Assert(!bytes.Equal(retKey1, retKey2))
}
