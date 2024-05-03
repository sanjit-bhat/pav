package ktmerkle

import (
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/secure-chat/cryptoffi"
	"github.com/mit-pdos/secure-chat/merkle"
	"github.com/tchajed/marshal"
)

type epochTy = uint64
type linkTy = []byte
type errorTy = bool
type okTy = bool

const (
	// Errors
	errNone errorTy = false
	errSome errorTy = true
	// RPCs
	rpcKeyServUpdateEpoch  uint64 = 1
	rpcKeyServPut          uint64 = 2
	rpcKeyServGetIdAtEpoch uint64 = 3
	rpcKeyServGetIdLatest  uint64 = 4
	rpcKeyServGetDigest    uint64 = 5
	rpcAuditorUpdate       uint64 = 1
	rpcAuditorGetLink      uint64 = 2
)

func SafeReadInt(b0 []byte) (uint64, []byte, errorTy) {
	var b = b0
	if uint64(len(b0)) < 8 {
		return 0, nil, errSome
	}
	data, b := marshal.ReadInt(b)
	return data, b, errNone
}

func SafeReadBytes(b0 []byte, length uint64) ([]byte, []byte, errorTy) {
	var b = b0
	if uint64(len(b)) < length {
		return nil, nil, errSome
	}
	data, b := marshal.ReadBytes(b, length)
	return data, b, errNone
}

func WriteBool(b0 []byte, data bool) []byte {
	var b = b0
	var data1 uint64
	if data {
		data1 = 1
	}
	b = marshal.WriteInt(b, data1)
	return b
}

func ReadBool(b0 []byte) (bool, []byte, errorTy) {
	var b = b0
	data, b, err := SafeReadInt(b)
	if err != errNone {
		return false, nil, err
	}
	var data1 bool
	if data != 0 {
		data1 = true
	}
	return data1, b, errNone
}

func WriteSlice1D(b0 []byte, data []byte) []byte {
	var b = b0
	b = marshal.WriteInt(b, uint64(len(data)))
	b = marshal.WriteBytes(b, data)
	return b
}

func WriteSlice2D(b0 []byte, data [][]byte) []byte {
	var b = b0
	b = marshal.WriteInt(b, uint64(len(data)))
	for _, data1 := range data {
		b = WriteSlice1D(b, data1)
	}
	return b
}

func WriteSlice3D(b0 []byte, data [][][]byte) []byte {
	var b = b0
	b = marshal.WriteInt(b, uint64(len(data)))
	for _, data1 := range data {
		b = WriteSlice2D(b, data1)
	}
	return b
}

func ReadSlice1D(b0 []byte) ([]byte, []byte, errorTy) {
	var b = b0
	length, b, err := SafeReadInt(b)
	if err != errNone {
		return nil, nil, err
	}
	data, b, err := SafeReadBytes(b, length)
	if err != errNone {
		return nil, nil, err
	}
	return data, b, errNone
}

func ReadSlice2D(b0 []byte) ([][]byte, []byte, errorTy) {
	var b = b0
	length, b, err := SafeReadInt(b)
	if err != errNone {
		return nil, nil, err
	}
	var data0 [][]byte
	var err0 errorTy
	var i uint64
	for ; i < length; i++ {
		var data1 []byte
		var err1 errorTy
		data1, b, err1 = ReadSlice1D(b)
		if err1 != errNone {
			err0 = err1
			continue
		}
		data0 = append(data0, data1)
	}
	if err0 != errNone {
		return nil, nil, err0
	}
	return data0, b, errNone
}

func ReadSlice3D(b0 []byte) ([][][]byte, []byte, errorTy) {
	var b = b0
	length, b, err := SafeReadInt(b)
	if err != errNone {
		return nil, nil, err
	}
	var data0 [][][]byte
	var err0 errorTy
	var i uint64
	for ; i < length; i++ {
		var data1 [][]byte
		var err1 errorTy
		data1, b, err1 = ReadSlice2D(b)
		if err1 != errNone {
			err0 = err1
			continue
		}
		data0 = append(data0, data1)
	}
	if err0 != errNone {
		return nil, nil, err0
	}
	return data0, b, errNone
}

type epochHash struct {
	epoch epochTy
	hash  []byte
}

func (o *epochHash) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.epoch)
	b = marshal.WriteBytes(b, o.hash)
	return b
}

func (o *epochHash) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	epoch, b, err := SafeReadInt(b)
	if err != errNone {
		return nil, err
	}
	hash, b, err := SafeReadBytes(b, cryptoffi.HashLen)
	if err != errNone {
		return nil, err
	}
	o.epoch = epoch
	o.hash = hash
	return b, errNone
}

type putArg struct {
	id  merkle.Id
	val merkle.Val
}

func (o *putArg) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteBytes(b, o.id)
	b = WriteSlice1D(b, o.val)
	return b
}

func (o *putArg) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	id, b, err := SafeReadBytes(b, cryptoffi.HashLen)
	if err != errNone {
		return nil, err
	}
	val, b, err := ReadSlice1D(b)
	if err != errNone {
		return nil, err
	}
	o.id = id
	o.val = val
	return b, errNone
}

type idValEpoch struct {
	id    merkle.Id
	val   merkle.Val
	epoch epochTy
}

func (o *idValEpoch) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteBytes(b, o.id)
	b = WriteSlice1D(b, o.val)
	b = marshal.WriteInt(b, o.epoch)
	return b
}

func (o *idValEpoch) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	id, b, err := SafeReadBytes(b, cryptoffi.HashLen)
	if err != errNone {
		return nil, err
	}
	val, b, err := ReadSlice1D(b)
	if err != errNone {
		return nil, err
	}
	epoch, b, err := SafeReadInt(b)
	if err != errNone {
		return nil, err
	}
	o.id = id
	o.val = val
	o.epoch = epoch
	return b, errNone
}

type putReply struct {
	epoch epochTy
	sig   cryptoffi.Sig
	error errorTy
}

func (o *putReply) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.epoch)
	b = marshal.WriteBytes(b, o.sig)
	b = WriteBool(b, o.error)
	return b
}

func (o *putReply) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	epoch, b, err := SafeReadInt(b)
	if err != errNone {
		return nil, err
	}
	sig, b, err := SafeReadBytes(b, cryptoffi.SigLen)
	if err != errNone {
		return nil, err
	}
	error, b, err := ReadBool(b)
	if err != errNone {
		return nil, err
	}
	o.sig = sig
	o.epoch = epoch
	o.error = error
	return b, errNone
}

func callPut(cli *urpc.Client, id merkle.Id, val merkle.Val) (epochTy, cryptoffi.Sig, errorTy) {
	argB := (&putArg{id: id, val: val}).encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(rpcKeyServPut, argB, &replyB, 100)
	if err0 != urpc.ErrNone {
		return 0, nil, errSome
	}
	reply := &putReply{}
	_, err1 := reply.decode(replyB)
	if err1 != errNone {
		return 0, nil, err1
	}
	return reply.epoch, reply.sig, reply.error
}

type getIdAtEpochArg struct {
	id    merkle.Id
	epoch epochTy
}

func (o *getIdAtEpochArg) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteBytes(b, o.id)
	b = marshal.WriteInt(b, o.epoch)
	return b
}

func (o *getIdAtEpochArg) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	id, b, err := SafeReadBytes(b, cryptoffi.HashLen)
	if err != errNone {
		return nil, err
	}
	epoch, b, err := SafeReadInt(b)
	if err != errNone {
		return nil, err
	}
	o.id = id
	o.epoch = epoch
	return b, errNone
}

type getIdAtEpochReply struct {
	digest merkle.Digest
	proof  merkle.Proof
	sig    cryptoffi.Sig
	error  errorTy
}

func (o *getIdAtEpochReply) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteBytes(b, o.digest)
	b = WriteSlice3D(b, o.proof)
	b = marshal.WriteBytes(b, o.sig)
	b = WriteBool(b, o.error)
	return b
}

func (o *getIdAtEpochReply) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	digest, b, err := SafeReadBytes(b, cryptoffi.HashLen)
	if err != errNone {
		return nil, err
	}
	proof, b, err := ReadSlice3D(b)
	if err != errNone {
		return nil, err
	}
	sig, b, err := SafeReadBytes(b, cryptoffi.SigLen)
	error, b, err := ReadBool(b)
	if err != errNone {
		return nil, err
	}
	o.digest = digest
	o.proof = proof
	o.sig = sig
	o.error = error
	return b, errNone
}

func callGetIdAtEpoch(cli *urpc.Client, id merkle.Id, epoch epochTy) *getIdAtEpochReply {
	errReply := &getIdAtEpochReply{}
	errReply.error = errSome
	argB := (&getIdAtEpochArg{id: id, epoch: epoch}).encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(rpcKeyServGetIdAtEpoch, argB, &replyB, 100)
	if err0 != urpc.ErrNone {
		return errReply
	}
	reply := &getIdAtEpochReply{}
	_, err1 := reply.decode(replyB)
	if err1 != errNone {
		return errReply
	}
	return reply
}

type getIdLatestArg struct {
	id merkle.Id
}

func (o *getIdLatestArg) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteBytes(b, o.id)
	return b
}

func (o *getIdLatestArg) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	id, b, err := SafeReadBytes(b, cryptoffi.HashLen)
	if err != errNone {
		return nil, err
	}
	o.id = id
	return b, errNone
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

func (o *getIdLatestReply) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.epoch)
	b = WriteSlice1D(b, o.val)
	b = marshal.WriteBytes(b, o.digest)
	b = WriteBool(b, o.proofTy)
	b = WriteSlice3D(b, o.proof)
	b = marshal.WriteBytes(b, o.sig)
	b = WriteBool(b, o.error)
	return b
}

func (o *getIdLatestReply) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	epoch, b, err := SafeReadInt(b)
	if err != errNone {
		return nil, err
	}
	val, b, err := ReadSlice1D(b)
	if err != errNone {
		return nil, err
	}
	digest, b, err := SafeReadBytes(b, cryptoffi.HashLen)
	if err != errNone {
		return nil, err
	}
	proofTy, b, err := ReadBool(b)
	if err != errNone {
		return nil, err
	}
	proof, b, err := ReadSlice3D(b)
	if err != errNone {
		return nil, err
	}
	sig, b, err := SafeReadBytes(b, cryptoffi.SigLen)
	if err != errNone {
		return nil, err
	}
	error, b, err := ReadBool(b)
	if err != errNone {
		return nil, err
	}
	o.epoch = epoch
	o.val = val
	o.digest = digest
	o.proofTy = proofTy
	o.proof = proof
	o.sig = sig
	o.error = error
	return b, errNone
}

func callGetIdLatest(cli *urpc.Client, id merkle.Id) *getIdLatestReply {
	errReply := &getIdLatestReply{}
	errReply.error = errSome
	argB := (&getIdLatestArg{id: id}).encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(rpcKeyServGetIdLatest, argB, &replyB, 100)
	if err0 != urpc.ErrNone {
		return errReply
	}
	reply := &getIdLatestReply{}
	_, err1 := reply.decode(replyB)
	if err1 != errNone {
		return errReply
	}
	return reply
}

type getDigestArg struct {
	epoch epochTy
}

func (o *getDigestArg) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.epoch)
	return b
}

func (o *getDigestArg) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	epoch, b, err := SafeReadInt(b)
	if err != errNone {
		return nil, err
	}
	o.epoch = epoch
	return b, errNone
}

type getDigestReply struct {
	digest merkle.Digest
	sig    cryptoffi.Sig
	error  errorTy
}

func (o *getDigestReply) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteBytes(b, o.digest)
	b = marshal.WriteBytes(b, o.sig)
	b = WriteBool(b, o.error)
	return b
}

func (o *getDigestReply) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	digest, b, err := SafeReadBytes(b, cryptoffi.HashLen)
	if err != errNone {
		return nil, err
	}
	sig, b, err := SafeReadBytes(b, cryptoffi.SigLen)
	if err != errNone {
		return nil, err
	}
	error, b, err := ReadBool(b)
	if err != errNone {
		return nil, err
	}
	o.digest = digest
	o.sig = sig
	o.error = error
	return b, errNone
}

func callGetDigest(cli *urpc.Client, epoch epochTy) (merkle.Digest, cryptoffi.Sig, errorTy) {
	argB := (&getDigestArg{epoch: epoch}).encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(rpcKeyServGetDigest, argB, &replyB, 100)
	if err0 != urpc.ErrNone {
		return nil, nil, errSome
	}
	reply := &getDigestReply{}
	_, err1 := reply.decode(replyB)
	if err1 != errNone {
		return nil, nil, err1
	}
	return reply.digest, reply.sig, reply.error
}

type updateArg struct {
	epoch  epochTy
	digest merkle.Digest
	sig    cryptoffi.Sig
}

func (o *updateArg) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.epoch)
	b = marshal.WriteBytes(b, o.digest)
	b = marshal.WriteBytes(b, o.sig)
	return b
}

func (o *updateArg) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	epoch, b, err := SafeReadInt(b)
	if err != errNone {
		return nil, err
	}
	digest, b, err := SafeReadBytes(b, cryptoffi.HashLen)
	if err != errNone {
		return nil, err
	}
	sig, b, err := SafeReadBytes(b, cryptoffi.SigLen)
	if err != errNone {
		return nil, err
	}
	o.epoch = epoch
	o.digest = digest
	o.sig = sig
	return b, errNone
}

type updateReply struct {
	error errorTy
}

func (o *updateReply) encode() []byte {
	var b = make([]byte, 0)
	b = WriteBool(b, o.error)
	return b
}

func (o *updateReply) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	error, b, err := ReadBool(b)
	if err != errNone {
		return nil, err
	}
	o.error = error
	return b, errNone
}

func callUpdate(cli *urpc.Client, epoch epochTy, dig merkle.Digest, sig cryptoffi.Sig) errorTy {
	argB := (&updateArg{epoch: epoch, digest: dig, sig: sig}).encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(rpcAuditorUpdate, argB, &replyB, 100)
	if err0 != urpc.ErrNone {
		return errSome
	}
	reply := &updateReply{}
	_, err1 := reply.decode(replyB)
	if err1 != errNone {
		return err1
	}
	return reply.error
}

type getLinkArg struct {
	epoch epochTy
}

func (o *getLinkArg) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.epoch)
	return b
}

func (o *getLinkArg) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	epoch, b, err := SafeReadInt(b)
	if err != errNone {
		return nil, err
	}
	o.epoch = epoch
	return b, errNone
}

type getLinkReply struct {
	link  linkTy
	sig   cryptoffi.Sig
	error errorTy
}

func (o *getLinkReply) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteBytes(b, o.link)
	b = marshal.WriteBytes(b, o.sig)
	b = WriteBool(b, o.error)
	return b
}

func (o *getLinkReply) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	link, b, err := SafeReadBytes(b, cryptoffi.HashLen)
	if err != errNone {
		return nil, err
	}
	sig, b, err := SafeReadBytes(b, cryptoffi.SigLen)
	if err != errNone {
		return nil, err
	}
	error, b, err := ReadBool(b)
	if err != errNone {
		return nil, err
	}
	o.link = link
	o.sig = sig
	o.error = error
	return b, errNone
}

func callGetLink(cli *urpc.Client, epoch epochTy) (linkTy, cryptoffi.Sig, errorTy) {
	argB := (&getLinkArg{epoch: epoch}).encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(rpcAuditorGetLink, argB, &replyB, 100)
	if err0 != urpc.ErrNone {
		return nil, nil, errSome
	}
	reply := &getLinkReply{}
	_, err1 := reply.decode(replyB)
	if err1 != errNone {
		return nil, nil, err1
	}
	return reply.link, reply.sig, reply.error
}
