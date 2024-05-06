package ktmerkle

import (
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/secure-chat/cryptoffi"
	"github.com/mit-pdos/secure-chat/merkle"
)

func verCallPut(cli *urpc.Client, pk cryptoffi.PublicKey, id merkle.Id, val merkle.Val) (epochTy, errorTy) {
	epoch, sig, err := callPut(cli, id, val)
	if err {
		return 0, err
	}
	enc := (&idValEpoch{id: id, val: val, epoch: epoch}).encode()
	ok := cryptoffi.Verify(pk, enc, sig)
	if !ok {
		return 0, errSome
	}
	return epoch, errNone
}

func verCallGetIdAtEpoch(cli *urpc.Client, pk cryptoffi.PublicKey, id merkle.Id, epoch epochTy) *getIdAtEpochReply {
	errReply := &getIdAtEpochReply{}
	errReply.error = errSome
	reply := callGetIdAtEpoch(cli, id, epoch)
	if reply.error {
		return errReply
	}
	enc := (&epochHash{epoch: epoch, hash: reply.digest}).encode()
	ok := cryptoffi.Verify(pk, enc, reply.sig)
	if !ok {
		return errReply
	}
	err := merkle.CheckProof(reply.proofTy, reply.proof, id, reply.val, reply.digest)
	if err {
		return errReply
	}
	return reply
}

func verCallGetIdLatest(cli *urpc.Client, pk cryptoffi.PublicKey, id merkle.Id) *getIdLatestReply {
	errReply := &getIdLatestReply{}
	errReply.error = errSome
	reply := callGetIdLatest(cli, id)
	if reply.error {
		return errReply
	}

	enc := (&epochHash{epoch: reply.epoch, hash: reply.digest}).encode()
	ok0 := cryptoffi.Verify(pk, enc, reply.sig)
	if !ok0 {
		return errReply
	}

	err := merkle.CheckProof(reply.proofTy, reply.proof, id, reply.val, reply.digest)
	if err {
		return errReply
	}
	return reply
}

func verCallGetDigest(cli *urpc.Client, pk cryptoffi.PublicKey, epoch epochTy) (merkle.Digest, errorTy) {
	dig, sig, err := callGetDigest(cli, epoch)
	if err {
		return nil, err
	}
	enc := (&epochHash{epoch: epoch, hash: dig}).encode()
	ok := cryptoffi.Verify(pk, enc, sig)
	if !ok {
		return nil, errSome
	}
	return dig, errNone
}

func verCallGetLink(cli *urpc.Client, pk cryptoffi.PublicKey, epoch epochTy) (linkTy, errorTy) {
	link, sig, err := callGetLink(cli, epoch)
	if err {
		return nil, err
	}

	enc := (&epochHash{epoch: epoch, hash: link}).encode()
	ok := cryptoffi.Verify(pk, enc, sig)
	if !ok {
		return nil, errSome
	}
	return link, errNone
}
