package ktMerkle

import (
	"bytes"
	"fmt"
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/secure-chat/cryptoShim"
	"github.com/mit-pdos/secure-chat/merkle"
	"sync"
	"testing"
	"time"
)

func TestBasicServ(t *testing.T) {
	servSk, _ := cryptoShim.MakeKeys()
	s := NewKeyServ(servSk)
	id := cryptoShim.Hash([]byte("id"))
	val := []byte("val")
	_, _, err := s.Put(id, val)
	if err != ErrNone {
		t.Fatal()
	}
    // TODO: maybe want to test sigs coming from these funcs?

	reply0 := s.GetIdLatest(id)
	if reply0.Error != ErrNone {
		t.Fatal()
	}
	err = merkle.CheckProof(merkle.NonmembProofTy, reply0.Proof, id, nil, reply0.Digest)
	if err != ErrNone {
		t.Fatal()
	}

	s.UpdateEpoch()

	reply0 = s.GetIdLatest(id)
	if reply0.Error != ErrNone {
		t.Fatal()
	}
	err = merkle.CheckProof(merkle.MembProofTy, reply0.Proof, id, val, reply0.Digest)
	if err != ErrNone {
		t.Fatal()
	}

	reply1 := s.GetIdAtEpoch(id, 1)
	if reply1.Error != ErrNone {
		t.Fatal()
	}
	err = merkle.CheckProof(merkle.MembProofTy, reply1.Proof, id, val, reply1.Digest)
	if err != ErrNone {
		t.Fatal()
	}

	dig1, _, err := s.GetDigest(1)
	if err != ErrNone {
		t.Fatal()
	}
	if !bytes.Equal(reply0.Digest, dig1) {
		t.Fatal()
	}
}

var port = 6060
var portMu = new(sync.Mutex)

func MakeUniqueAddr() uint64 {
	portMu.Lock()
	ip := fmt.Sprintf("0.0.0.0:%d", port)
	addr := grove_ffi.MakeAddress(ip)
	port++
	portMu.Unlock()
	return addr
}

// Until we have proof tests for everything, this provides coverage.
func TestBasicAll(t *testing.T) {
	servAddr := MakeUniqueAddr()
    servSk, servVk := cryptoShim.MakeKeys()
	go func() {
		s := NewKeyServ(servSk)
		s.Start(servAddr)
	}()

	adtrSk, adtrVk := cryptoShim.MakeKeys()
	adtrVks := []cryptoShim.VerifierT{adtrVk}
	adtrAddr := MakeUniqueAddr()
	adtrAddrs := []grove_ffi.Address{adtrAddr}
	go func() {
		a := NewAuditor(adtrSk, servVk)
		a.Start(adtrAddr)
	}()

	time.Sleep(time.Millisecond)
	servCli := urpc.MakeClient(servAddr)
	adtrCli := urpc.MakeClient(adtrAddr)

	// Create hist with [None, val0, val0, val1, val1].
	emptyReplyB := make([]byte, 0)
	err := servCli.Call(RpcKeyServUpdateEpoch, nil, &emptyReplyB, 100)
	if err != ErrNone {
		t.Fatal()
	}

	aliceId := cryptoShim.Hash([]byte("alice"))
	alice := NewKeyCli(aliceId, servAddr, adtrAddrs, adtrVks, servVk)
	val0 := []byte("val0")
	err = alice.Put(val0)
	if err != ErrNone {
		t.Fatal()
	}

	err = servCli.Call(RpcKeyServUpdateEpoch, nil, &emptyReplyB, 100)
	if err != ErrNone {
		t.Fatal()
	}
	err = servCli.Call(RpcKeyServUpdateEpoch, nil, &emptyReplyB, 100)
	if err != ErrNone {
		t.Fatal()
	}

	val1 := []byte("val1")
	err = alice.Put(val1)
	if err != ErrNone {
		t.Fatal()
	}

	err = servCli.Call(RpcKeyServUpdateEpoch, nil, &emptyReplyB, 100)
	if err != ErrNone {
		t.Fatal()
	}
	err = servCli.Call(RpcKeyServUpdateEpoch, nil, &emptyReplyB, 100)
	if err != ErrNone {
		t.Fatal()
	}

	epoch := alice.SelfAudit()
	if err != ErrNone {
		t.Fatal()
	}
	expMaxEpochExcl := uint64(6)
	if epoch != expMaxEpochExcl {
		t.Fatal(epoch)
	}

	var digs []merkle.Digest
    var sigs []cryptoShim.Sig
	for epoch := uint64(0); ; epoch++ {
		dig, sig, err := CallGetDigest(servCli, epoch)
		if err != ErrNone {
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
		err := CallUpdate(adtrCli, uint64(epoch), dig, sig)
		if err != ErrNone {
			t.Fatal()
		}
	}

	bob := NewKeyCli(nil, servAddr, adtrAddrs, adtrVks, servVk)
	epoch, val2, err := bob.Get(aliceId)
	if err != ErrNone {
		t.Fatal()
	}
	if epoch != expMaxEpochExcl {
		t.Fatal(epoch)
	}
	if !bytes.Equal(val1, val2) {
		t.Fatal(val1, val2)
	}
	epoch, err = bob.Audit(0)
	if err != ErrNone {
		t.Fatal()
	}
	if epoch != expMaxEpochExcl {
		t.Fatal(epoch)
	}
}

func TestAgreement(t *testing.T) {
	servAddr := MakeUniqueAddr()
	adtrAddr := MakeUniqueAddr()
	testAgreement(servAddr, adtrAddr)
}
