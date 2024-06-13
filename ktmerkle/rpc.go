package ktmerkle

import (
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/merkle"
)

// servSigSepDig is the server's signature domain separation digest msg.
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

type servGetIdAtEpochArg struct {
	// rpc: invariant: len 32.
	id    merkle.Id
	epoch epochTy
}

type servGetIdAtEpochReply struct {
	val merkle.Val
	// rpc: invariant: len 32.
	digest  merkle.Digest
	proofTy merkle.ProofTy
	proof   merkle.Proof
	// rpc: invariant: len 64.
	sig   cryptoffi.Sig
	error errorTy
}

type servGetIdLatestArg struct {
	// rpc: invariant: len 32.
	id merkle.Id
}

type servGetIdLatestReply struct {
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

type servGetDigestArg struct {
	epoch epochTy
}

type servGetDigestReply struct {
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
	epoch epochTy
	// rpc: invariant: len 32.
	link linkTy
	// rpc: invariant: len 64.
	sig cryptoffi.Sig
}

type adtrGetArg struct {
	epoch epochTy
}

type adtrGetReply struct {
	// rpc: invariant: len 32.
	link linkTy
	// rpc: invariant: len 64.
	sig   cryptoffi.Sig
	error errorTy
}
