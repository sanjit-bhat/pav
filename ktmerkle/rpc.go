package ktmerkle

import (
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/merkle"
)

type epochHash struct {
	epoch epochTy
	// Invariant: len 32.
	hash []byte
}

type putArg struct {
	// Invariant: len 32.
	id  merkle.Id
	val merkle.Val
}

type idValEpoch struct {
	// Invariant: len 32.
	id    merkle.Id
	val   merkle.Val
	epoch epochTy
}

type putReply struct {
	epoch epochTy
	// Invariant: len 64.
	sig   cryptoffi.Sig
	error errorTy
}

type getIdAtEpochArg struct {
	// Invariant: len 32.
	id    merkle.Id
	epoch epochTy
}

type getIdAtEpochReply struct {
	val merkle.Val
	// Invariant: len 32.
	digest  merkle.Digest
	proofTy merkle.ProofTy
	proof   merkle.Proof
	// Invariant: len 64.
	sig   cryptoffi.Sig
	error errorTy
}

type getIdLatestArg struct {
	// Invariant: len 32.
	id merkle.Id
}

type getIdLatestReply struct {
	epoch epochTy
	val   merkle.Val
	// Invariant: len 32.
	digest  merkle.Digest
	proofTy merkle.ProofTy
	proof   merkle.Proof
	// Invariant: len 64.
	sig   cryptoffi.Sig
	error errorTy
}

type getDigestArg struct {
	epoch epochTy
}

type getDigestReply struct {
	// Invariant: len 32.
	digest merkle.Digest
	// Invariant: len 64.
	sig   cryptoffi.Sig
	error errorTy
}

type updateArg struct {
	epoch epochTy
	// Invariant: len 32.
	digest merkle.Digest
	// Invariant: len 64.
	sig cryptoffi.Sig
}

type updateReply struct {
	error errorTy
}

type getLinkArg struct {
	epoch epochTy
}

type getLinkReply struct {
	// Invariant: len 32.
	link linkTy
	// Invariant: len 64.
	sig   cryptoffi.Sig
	error errorTy
}
