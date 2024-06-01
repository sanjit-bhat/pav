package ktmerkle

import (
	"bytes"
	"fmt"
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/secure-chat/cryptoffi"
	"github.com/mit-pdos/secure-chat/merkle"
	"sync"
	"testing"
	"time"
)

func TestBasicServ(t *testing.T) {
	servSk, servPk := cryptoffi.MakeKeys()
	s := newKeyServ(servSk)
	id := cryptoffi.Hash([]byte("id"))
	val := []byte("val")
	epoch, sig, err := s.put(id, val)
	if err {
		t.Fatal()
	}
	if epoch != 1 {
		t.Fatal(epoch)
	}
	enc0 := (&idValEpoch{id: id, val: val, epoch: epoch}).encode()
	ok := cryptoffi.Verify(servPk, enc0, sig)
	if !ok {
		t.Fatal()
	}

	reply0 := s.getIdLatest(id)
	if reply0.error {
		t.Fatal()
	}
	enc1 := (&epochHash{epoch: reply0.epoch, hash: reply0.digest}).encode()
	ok = cryptoffi.Verify(servPk, enc1, reply0.sig)
	if !ok {
		t.Fatal()
	}
	err = merkle.CheckProof(merkle.NonmembProofTy, reply0.proof, id, nil, reply0.digest)
	if err {
		t.Fatal()
	}

	s.updateEpoch()

	reply0 = s.getIdLatest(id)
	if reply0.error {
		t.Fatal()
	}
	enc1 = (&epochHash{epoch: reply0.epoch, hash: reply0.digest}).encode()
	ok = cryptoffi.Verify(servPk, enc1, reply0.sig)
	if !ok {
		t.Fatal()
	}
	err = merkle.CheckProof(merkle.MembProofTy, reply0.proof, id, val, reply0.digest)
	if err {
		t.Fatal()
	}

	reply1 := s.getIdAtEpoch(id, 1)
	if reply1.error {
		t.Fatal()
	}
	enc1 = (&epochHash{epoch: 1, hash: reply1.digest}).encode()
	ok = cryptoffi.Verify(servPk, enc1, reply1.sig)
	if !ok {
		t.Fatal()
	}
	err = merkle.CheckProof(merkle.MembProofTy, reply1.proof, id, val, reply1.digest)
	if err {
		t.Fatal()
	}

	dig1, sig, err := s.getDigest(1)
	if err {
		t.Fatal()
	}
	if !bytes.Equal(reply0.digest, dig1) {
		t.Fatal()
	}
	enc1 = (&epochHash{epoch: 1, hash: dig1}).encode()
	ok = cryptoffi.Verify(servPk, enc1, sig)
	if !ok {
		t.Fatal()
	}
}

var port = 6060
var portMu = new(sync.Mutex)

func makeUniqueAddr() uint64 {
	portMu.Lock()
	ip := fmt.Sprintf("0.0.0.0:%d", port)
	addr := grove_ffi.MakeAddress(ip)
	port++
	portMu.Unlock()
	return addr
}

// TestBasicAll provides coverage for all funcs.
// Useful until we make proof tests.
func TestBasicAll(t *testing.T) {
	servAddr := makeUniqueAddr()
	servSk, servPk := cryptoffi.MakeKeys()
	go func() {
		s := newKeyServ(servSk)
		s.start(servAddr)
	}()

	adtrSk, adtrPk := cryptoffi.MakeKeys()
	adtrPks := []cryptoffi.PublicKey{adtrPk}
	adtrAddr := makeUniqueAddr()
	adtrAddrs := []grove_ffi.Address{adtrAddr}
	go func() {
		a := newAuditor(adtrSk, servPk)
		a.start(adtrAddr)
	}()

	time.Sleep(time.Millisecond)
	servCli := urpc.MakeClient(servAddr)
	adtrCli := urpc.MakeClient(adtrAddr)

	// Create hist with [None, val0, val0, val1, val1].
	aliceId := cryptoffi.Hash([]byte("alice"))
	alice := newKeyCli(aliceId, servAddr, adtrAddrs, adtrPks, servPk)
	val0 := []byte("val0")
	epoch, err := alice.put(val0)
	if err {
		t.Fatal()
	}
	if epoch != 1 {
		t.Fatal(epoch)
	}

	emptyReplyB := make([]byte, 0)
	errRpc := servCli.Call(rpcKeyServUpdateEpoch, nil, &emptyReplyB, 100)
	if errRpc != urpc.ErrNone {
		t.Fatal()
	}
	errRpc = servCli.Call(rpcKeyServUpdateEpoch, nil, &emptyReplyB, 100)
	if errRpc != urpc.ErrNone {
		t.Fatal()
	}

	val1 := []byte("val1")
	epoch, err = alice.put(val1)
	if err {
		t.Fatal()
	}
	if epoch != 3 {
		t.Fatal(epoch)
	}

	errRpc = servCli.Call(rpcKeyServUpdateEpoch, nil, &emptyReplyB, 100)
	if errRpc != urpc.ErrNone {
		t.Fatal()
	}
	errRpc = servCli.Call(rpcKeyServUpdateEpoch, nil, &emptyReplyB, 100)
	if errRpc != urpc.ErrNone {
		t.Fatal()
	}

	selfAuditEpoch := alice.selfAudit()
	expMaxEpochExcl := uint64(5)
	if selfAuditEpoch != expMaxEpochExcl {
		t.Fatal(selfAuditEpoch)
	}

	var digs []merkle.Digest
	var sigs []cryptoffi.Sig
	for epoch := uint64(0); ; epoch++ {
		dig, sig, err := callGetDigest(servCli, epoch)
		if err {
			break
		}
		digs = append(digs, dig)
		sigs = append(sigs, sig)
	}
	numDigs := uint64(len(digs))
	if numDigs != expMaxEpochExcl {
		t.Fatal(numDigs)
	}

	for epoch, dig := range digs {
		sig := sigs[epoch]
		err := callUpdate(adtrCli, uint64(epoch), dig, sig)
		if err {
			t.Fatal()
		}
	}

	bob := newKeyCli(nil, servAddr, adtrAddrs, adtrPks, servPk)
	getEpoch, val2, err := bob.get(aliceId)
	if err {
		t.Fatal()
	}
	if getEpoch != expMaxEpochExcl-1 {
		t.Fatal(getEpoch)
	}
	if !bytes.Equal(val1, val2) {
		t.Fatal(val1, val2)
	}
	auditEpoch, err := bob.audit(0)
	if err {
		t.Fatal()
	}
	if auditEpoch != expMaxEpochExcl {
		t.Fatal(auditEpoch)
	}
}

func TestAgreement(t *testing.T) {
	servAddr := makeUniqueAddr()
	adtrAddr := makeUniqueAddr()
	testAgreement(servAddr, adtrAddr)
}
