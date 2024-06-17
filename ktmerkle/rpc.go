package ktmerkle

import (
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/merkle"
)

// Sep structs are for domain separation.

// rpc: no decode needed.
type adtrSigSepLink struct {
	// rpc: invariant: const 0.
	tag   byte
	epoch epochTy
	// rpc: invariant: len 32.
	link linkTy
}

// rpc: no decode needed.
type servSigSepDig struct {
	// rpc: invariant: const 0.
	tag   byte
	epoch epochTy
	// rpc: invariant: len 32.
	dig merkle.Digest
}

// rpc: no decode needed.
type servSigSepLink struct {
	// rpc: invariant: const 1.
	tag   byte
	epoch epochTy
	// rpc: invariant: len 32.
	link linkTy
}

// rpc: no decode needed.
type servSigSepPut struct {
	// rpc: invariant: const 2.
	tag   byte
	epoch epochTy
	// rpc: invariant: len 32.
	id  merkle.Id
	val merkle.Val
}

type servRegArg struct {
	// rpc: invariant: len 32.
	id merkle.Id
	// rpc: invariant: len 32.
	pk cryptoffi.PublicKey
}

type servRegReply struct {
	error errorTy
}

type servPutArg struct {
	// rpc: invariant: len 32.
	id  merkle.Id
	val merkle.Val
}

type servPutReply struct {
	epoch epochTy
	// rpc: invariant: len 64.
	sig   cryptoffi.Sig
	error errorTy
}

type servGetIdAtArg struct {
	// rpc: invariant: len 32.
	id    merkle.Id
	epoch epochTy
}

type servGetIdAtReply struct {
	val merkle.Val
	// rpc: invariant: len 32.
	digest  merkle.Digest
	proofTy merkle.ProofTy
	proof   merkle.Proof
	// rpc: invariant: len 64.
	sig   cryptoffi.Sig
	error errorTy
}

type servGetIdNowArg struct {
	// rpc: invariant: len 32.
	id merkle.Id
}

type servGetIdNowReply struct {
	epoch epochTy
	val   merkle.Val
	// rpc: invariant: len 32.
	digest  merkle.Digest
	proofTy merkle.ProofTy
	proof   merkle.Proof
	// rpc: invariant: len 64.
	sig   cryptoffi.Sig
	error errorTy
}

type servGetDigArg struct {
	epoch epochTy
}

type servGetDigReply struct {
	// rpc: invariant: len 32.
	digest merkle.Digest
	// rpc: invariant: len 64.
	sig   cryptoffi.Sig
	error errorTy
}

type servGetLinkArg struct {
	epoch epochTy
}

type servGetLinkReply struct {
	// rpc: invariant: len 32.
	link linkTy
	// rpc: invariant: len 64.
	sig   cryptoffi.Sig
	error errorTy
}

type adtrPutArg struct {
	// rpc: invariant: len 32.
	link linkTy
	// rpc: invariant: len 64.
	sig cryptoffi.Sig
}

type adtrPutReply struct {
	error errorTy
}

type adtrGetArg struct {
	epoch epochTy
}

type adtrGetReply struct {
	// rpc: invariant: len 32.
	link linkTy
	// rpc: invariant: len 64.
	servSig cryptoffi.Sig
	// rpc: invariant: len 64.
	adtrSig cryptoffi.Sig
	error   errorTy
}
