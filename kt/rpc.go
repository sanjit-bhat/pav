package kt

import (
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/merkle"
)

// Sep structs are for domain separation.

// rpc: no decode needed.
type chainSepNone struct {
	//lint:ignore U1000 a const is still inserted into the rpc msg.
	// rpc: invariant: const 0.
	tag byte
}

// rpc: no decode needed.
type chainSepSome struct {
	//lint:ignore U1000 a const is still inserted into the rpc msg.
	// rpc: invariant: const 1.
	tag      byte
	epoch    epochTy
	prevLink linkTy
	data     []byte
}

// rpc: no decode needed.
type adtrSepLink struct {
	//lint:ignore U1000 a const is still inserted into the rpc msg.
	// rpc: invariant: const 0.
	tag  byte
	link linkTy
}

// rpc: no decode needed.
type servSepLink struct {
	// TODO: get rid of tag field.
	//lint:ignore U1000 a const is still inserted into the rpc msg.
	// rpc: invariant: const 0.
	tag  byte
	link linkTy
}

// rpc: no decode needed.
type servSepPut struct {
	//lint:ignore U1000 a const is still inserted into the rpc msg.
	// rpc: invariant: const 1.
	tag   byte
	epoch epochTy
	id    merkle.Id
	val   merkle.Val
}

type servPutArg struct {
	id  merkle.Id
	val merkle.Val
}

type servPutReply struct {
	putEpoch epochTy
	prevLink linkTy
	dig      merkle.Digest
	linkSig  cryptoffi.Sig
	putSig   cryptoffi.Sig
	error    errorTy
}

type servGetIdAtArg struct {
	id    merkle.Id
	epoch epochTy
}

type servGetIdAtReply struct {
	prevLink linkTy
	dig      merkle.Digest
	sig      cryptoffi.Sig
	val      merkle.Val
	proofTy  merkle.ProofTy
	proof    merkle.Proof
	error    errorTy
}

/*
type servGetIdNowArg struct {
	id merkle.Id
}

type servGetIdNowReply struct {
	epoch epochTy
	prevLink linkTy
	dig merkle.Digest
	sig     cryptoffi.Sig
	val     merkle.Val
	proofTy merkle.ProofTy
	proof   merkle.Proof
	error   errorTy
}
*/

type servGetLinkArg struct {
	epoch epochTy
}

type servGetLinkReply struct {
	prevLink linkTy
	dig      merkle.Digest
	sig      cryptoffi.Sig
	error    errorTy
}

type adtrPutArg struct {
	prevLink linkTy
	dig      merkle.Digest
	servSig  cryptoffi.Sig
}

type adtrPutReply struct {
	error errorTy
}

type adtrGetArg struct {
	epoch epochTy
}

type adtrGetReply struct {
	prevLink linkTy
	dig      merkle.Digest
	servSig  cryptoffi.Sig
	adtrSig  cryptoffi.Sig
	error    errorTy
}
