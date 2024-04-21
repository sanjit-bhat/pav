package ktMerkle

import (
	"bytes"
	"fmt"
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/secure-chat/crypto/ffi"
	"github.com/mit-pdos/secure-chat/merkle"
	"sync"
	"testing"
	"time"
)

func TestBasicServ(t *testing.T) {
	s := NewKeyServ()
	id := ffi.Hash([]byte("id"))
	val := []byte("val")
	_, err := s.Put(id, val)
	if err != ErrNone {
		t.Fatal()
	}

	_, _, dig0, _, proof, err := s.GetIdLatest(id)
	if err != ErrNone {
		t.Fatal()
	}
	err = merkle.CheckProof(merkle.NonmembProofTy, proof, id, nil, dig0)
	if err != ErrNone {
		t.Fatal()
	}

	s.UpdateEpoch()

	_, _, dig0, _, proof, err = s.GetIdLatest(id)
	if err != ErrNone {
		t.Fatal()
	}
	err = merkle.CheckProof(merkle.MembProofTy, proof, id, val, dig0)
	if err != ErrNone {
		t.Fatal()
	}

	_, dig0, _, proof, err = s.GetIdAtEpoch(id, 1)
	if err != ErrNone {
		t.Fatal()
	}
	err = merkle.CheckProof(merkle.MembProofTy, proof, id, val, dig0)
	if err != ErrNone {
		t.Fatal()
	}

	dig1, err := s.GetDigest(1)
	if err != ErrNone {
		t.Fatal()
	}
	if !bytes.Equal(dig0, dig1) {
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

func TestBasicAll(t *testing.T) {
	servAddr := MakeUniqueAddr()
	go func() {
		s := NewKeyServ()
		s.Start(servAddr)
	}()

	sk, vk := ffi.MakeKeys()
	adtrVks := []ffi.VerifierT{vk}
	adtrAddr := MakeUniqueAddr()
	adtrAddrs := []grove_ffi.Address{adtrAddr}
	go func() {
		a := NewAuditor(sk)
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

	aliceId := ffi.Hash([]byte("alice"))
	alice := NewKeyCli(aliceId, servAddr, adtrAddrs, adtrVks)
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

	epoch, err := alice.SelfAudit()
	if err != ErrNone {
		t.Fatal()
	}
	expMaxEpoch := uint64(4)
	if epoch != expMaxEpoch {
		t.Fatal(epoch)
	}

	var digs []merkle.Digest
	for epoch := uint64(0); ; epoch++ {
		dig, err := CallGetDigest(servCli, epoch)
		if err != ErrNone {
			break
		}
		digs = append(digs, dig)
	}
	numDigs := uint64(len(digs))
	if numDigs != expMaxEpoch+1 {
		t.Fatal(numDigs)
	}

	for _, dig := range digs {
		err := CallUpdate(adtrCli, dig)
		if err != ErrNone {
			t.Fatal()
		}
	}

	bob := NewKeyCli(nil, servAddr, adtrAddrs, adtrVks)
	epoch, err = bob.Audit(0)
	if err != ErrNone {
		t.Fatal()
	}
	if epoch != expMaxEpoch {
		t.Fatal(epoch)
	}
}
