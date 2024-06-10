package ktmerkle

import (
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/merkle"
)

type epochHash struct {
	epoch epochTy
	hash  []byte
}

type putArg struct {
	id  merkle.Id
	val merkle.Val
}

type idValEpoch struct {
	id    merkle.Id
	val   merkle.Val
	epoch epochTy
}

type putReply struct {
	epoch epochTy
	sig   cryptoffi.Sig
	error errorTy
}

type getIdAtEpochArg struct {
	id    merkle.Id
	epoch epochTy
}

type getIdAtEpochReply struct {
	val     merkle.Val
	digest  merkle.Digest
	proofTy merkle.ProofTy
	proof   merkle.Proof
	sig     cryptoffi.Sig
	error   errorTy
}

type getIdLatestArg struct {
	id merkle.Id
}

type getIdLatestReply struct {
	epoch   epochTy
	val     merkle.Val
	digest  merkle.Digest
	proofTy merkle.ProofTy
	proof   merkle.Proof
	sig     cryptoffi.Sig
	error   errorTy
}

type getDigestArg struct {
	epoch epochTy
}

type getDigestReply struct {
	digest merkle.Digest
	sig    cryptoffi.Sig
	error  errorTy
}

type updateArg struct {
	epoch  epochTy
	digest merkle.Digest
	sig    cryptoffi.Sig
}

type updateReply struct {
	error errorTy
}

type getLinkArg struct {
	epoch epochTy
}

type getLinkReply struct {
	link  linkTy
	sig   cryptoffi.Sig
	error errorTy
}
