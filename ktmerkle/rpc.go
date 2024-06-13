package ktmerkle

import (
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/merkle"
)

// rpc: no decode needed.
type signedDig struct {
	// rpc: invariant: const 0.
	tag   byte
	epoch epochTy
	// rpc: invariant: len 32.
	dig merkle.Digest
}

// rpc: no decode needed.
type signedLink struct {
	// rpc: invariant: const 1.
	tag   byte
	epoch epochTy
	// rpc: invariant: len 32.
	link linkTy
}

// rpc: no decode needed.
type signedPutPromise struct {
	// rpc: invariant: const 2.
	tag   byte
	epoch epochTy
	// rpc: invariant: len 32.
	id  merkle.Id
	val merkle.Val
}

// rpc: no decode needed.
type epochHash struct {
	epoch epochTy
	// rpc: invariant: len 32.
	hash []byte
}

// rpc: no decode needed.
type idValEpoch struct {
	// rpc: invariant: len 32.
	id    merkle.Id
	val   merkle.Val
	epoch epochTy
}

type putArg struct {
	// rpc: invariant: len 32.
	id  merkle.Id
	val merkle.Val
}

type putReply struct {
	epoch epochTy
	// rpc: invariant: len 64.
	sig   cryptoffi.Sig
	error errorTy
}

type getIdAtEpochArg struct {
	// rpc: invariant: len 32.
	id    merkle.Id
	epoch epochTy
}

type getIdAtEpochReply struct {
	val merkle.Val
	// rpc: invariant: len 32.
	digest  merkle.Digest
	proofTy merkle.ProofTy
	proof   merkle.Proof
	// rpc: invariant: len 64.
	sig   cryptoffi.Sig
	error errorTy
}

type getIdLatestArg struct {
	// rpc: invariant: len 32.
	id merkle.Id
}

type getIdLatestReply struct {
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

type getDigestArg struct {
	epoch epochTy
}

type getDigestReply struct {
	// rpc: invariant: len 32.
	digest merkle.Digest
	// rpc: invariant: len 64.
	sig   cryptoffi.Sig
	error errorTy
}

type updateArg struct {
	epoch epochTy
	// rpc: invariant: len 32.
	digest merkle.Digest
	// rpc: invariant: len 64.
	sig cryptoffi.Sig
}

type updateReply struct {
	error errorTy
}

type getLinkArg struct {
	epoch epochTy
}

type getLinkReply struct {
	// rpc: invariant: len 32.
	link linkTy
	// rpc: invariant: len 64.
	sig   cryptoffi.Sig
	error errorTy
}
