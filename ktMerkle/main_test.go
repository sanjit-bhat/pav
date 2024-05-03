package ktMerkle

import (
	"bytes"
	"fmt"
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/secure-chat/cryptoFFI"
	"github.com/mit-pdos/secure-chat/merkle"
	"sync"
	"testing"
	"time"
)

func TestBasicServ(t *testing.T) {
	servSk, _ := cryptoFFI.MakeKeys()
	s := newKeyServ(servSk)
	id := cryptoFFI.Hash([]byte("id"))
	val := []byte("val")
	_, _, err := s.put(id, val)
	if err != errNone {
		t.Fatal()
	}
	// TODO: maybe want to test sigs coming from these funcs?

	reply0 := s.getIdLatest(id)
	if reply0.error != errNone {
		t.Fatal()
	}
	err = merkle.CheckProof(merkle.NonmembProofTy, reply0.proof, id, nil, reply0.digest)
	if err != errNone {
		t.Fatal()
	}

	s.updateEpoch()

	reply0 = s.getIdLatest(id)
	if reply0.error != errNone {
		t.Fatal()
	}
	err = merkle.CheckProof(merkle.MembProofTy, reply0.proof, id, val, reply0.digest)
	if err != errNone {
		t.Fatal()
	}

	reply1 := s.getIdAtEpoch(id, 1)
	if reply1.error != errNone {
		t.Fatal()
	}
	err = merkle.CheckProof(merkle.MembProofTy, reply1.proof, id, val, reply1.digest)
	if err != errNone {
		t.Fatal()
	}

	dig1, _, err := s.getDigest(1)
	if err != errNone {
		t.Fatal()
	}
	if !bytes.Equal(reply0.digest, dig1) {
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

// Until we have proof tests for everything, this provides coverage.
func TestBasicAll(t *testing.T) {
	servAddr := makeUniqueAddr()
	servSk, servVk := cryptoFFI.MakeKeys()
	go func() {
		s := newKeyServ(servSk)
		s.start(servAddr)
	}()

	adtrSk, adtrVk := cryptoFFI.MakeKeys()
	adtrVks := []cryptoFFI.VerifierT{adtrVk}
	adtrAddr := makeUniqueAddr()
	adtrAddrs := []grove_ffi.Address{adtrAddr}
	go func() {
		a := newAuditor(adtrSk, servVk)
		a.start(adtrAddr)
	}()

	time.Sleep(time.Millisecond)
	servCli := urpc.MakeClient(servAddr)
	adtrCli := urpc.MakeClient(adtrAddr)

	// Create hist with [None, val0, val0, val1, val1].
	emptyReplyB := make([]byte, 0)
	errRpc := servCli.Call(rpcKeyServUpdateEpoch, nil, &emptyReplyB, 100)
	if errRpc != urpc.ErrNone {
		t.Fatal()
	}

	aliceId := cryptoFFI.Hash([]byte("alice"))
	alice := newKeyCli(aliceId, servAddr, adtrAddrs, adtrVks, servVk)
	val0 := []byte("val0")
    _, err := alice.put(val0)
    // TODO: maybe test alice Put epoch output
	if err != errNone {
		t.Fatal()
	}

	errRpc = servCli.Call(rpcKeyServUpdateEpoch, nil, &emptyReplyB, 100)
	if errRpc != urpc.ErrNone {
		t.Fatal()
	}
	errRpc = servCli.Call(rpcKeyServUpdateEpoch, nil, &emptyReplyB, 100)
	if errRpc != urpc.ErrNone {
		t.Fatal()
	}

	val1 := []byte("val1")
	_, err = alice.put(val1)
	if err != errNone {
		t.Fatal()
	}

	errRpc = servCli.Call(rpcKeyServUpdateEpoch, nil, &emptyReplyB, 100)
	if errRpc != urpc.ErrNone {
		t.Fatal()
	}
	errRpc = servCli.Call(rpcKeyServUpdateEpoch, nil, &emptyReplyB, 100)
	if errRpc != urpc.ErrNone {
		t.Fatal()
	}

	epoch := alice.selfAudit()
	expMaxEpochExcl := uint64(6)
	if epoch != expMaxEpochExcl {
		t.Fatal(epoch)
	}

	var digs []merkle.Digest
	var sigs []cryptoFFI.Sig
	for epoch := uint64(0); ; epoch++ {
		dig, sig, err := callGetDigest(servCli, epoch)
		if err != errNone {
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
		if err != errNone {
			t.Fatal()
		}
	}

	bob := newKeyCli(nil, servAddr, adtrAddrs, adtrVks, servVk)
	epoch, val2, err := bob.get(aliceId)
	if err != errNone {
		t.Fatal()
	}
	if epoch != expMaxEpochExcl {
		t.Fatal(epoch)
	}
	if !bytes.Equal(val1, val2) {
		t.Fatal(val1, val2)
	}
	epoch, err = bob.audit(0)
	if err != errNone {
		t.Fatal()
	}
	if epoch != expMaxEpochExcl {
		t.Fatal(epoch)
	}
}

func TestAgreement(t *testing.T) {
	servAddr := makeUniqueAddr()
	adtrAddr := makeUniqueAddr()
	testAgreement(servAddr, adtrAddr)
}
