package ktMerkle

import (
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/secure-chat/cryptoShim"
	"github.com/mit-pdos/secure-chat/merkle"
	"github.com/tchajed/marshal"
)

type Epoch = uint64
type Link = []byte
type Error = uint64

const (
	// Errors
	ErrNone Error = 0
	ErrSome Error = 1
	// RPCs
	RpcKeyServUpdateEpoch  uint64 = 1
	RpcKeyServPut          uint64 = 2
	RpcKeyServGetIdAtEpoch uint64 = 3
	RpcKeyServGetIdLatest  uint64 = 4
	RpcKeyServGetDigest    uint64 = 5
	RpcAuditorUpdate       uint64 = 1
	RpcAuditorGetLink      uint64 = 2
)

func SafeReadInt(b0 []byte) (uint64, []byte, Error) {
	var b = b0
	if uint64(len(b0)) < 8 {
		return 0, nil, ErrSome
	}
	data, b := marshal.ReadInt(b)
	return data, b, ErrNone
}

func SafeReadBytes(b0 []byte, length uint64) ([]byte, []byte, Error) {
	var b = b0
	if uint64(len(b)) < length {
		return nil, nil, ErrSome
	}
	data, b := marshal.ReadBytes(b, length)
	return data, b, ErrNone
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

func ReadBool(b0 []byte) (bool, []byte, Error) {
	var b = b0
	data, b, err := SafeReadInt(b)
	if err != ErrNone {
		return false, nil, err
	}
	var data1 bool
	if data != 0 {
		data1 = true
	}
	return data1, b, ErrNone
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

func ReadSlice1D(b0 []byte) ([]byte, []byte, Error) {
	var b = b0
	length, b, err := SafeReadInt(b)
	if err != ErrNone {
		return nil, nil, err
	}
	data, b, err := SafeReadBytes(b, length)
	if err != ErrNone {
		return nil, nil, err
	}
	return data, b, ErrNone
}

func ReadSlice2D(b0 []byte) ([][]byte, []byte, Error) {
	var b = b0
	length, b, err := SafeReadInt(b)
	if err != ErrNone {
		return nil, nil, err
	}
	var data0 [][]byte
	var err0 Error
	var i uint64
	for ; i < length; i++ {
		var data1 []byte
		var err1 Error
		data1, b, err1 = ReadSlice1D(b)
		if err1 != ErrNone {
			err0 = err1
			continue
		}
		data0 = append(data0, data1)
	}
	if err0 != ErrNone {
		return nil, nil, err0
	}
	return data0, b, ErrNone
}

func ReadSlice3D(b0 []byte) ([][][]byte, []byte, Error) {
	var b = b0
	length, b, err := SafeReadInt(b)
	if err != ErrNone {
		return nil, nil, err
	}
	var data0 [][][]byte
	var err0 Error
	var i uint64
	for ; i < length; i++ {
		var data1 [][]byte
		var err1 Error
		data1, b, err1 = ReadSlice2D(b)
		if err1 != ErrNone {
			err0 = err1
			continue
		}
		data0 = append(data0, data1)
	}
	if err0 != ErrNone {
		return nil, nil, err0
	}
	return data0, b, ErrNone
}

type EpochHash struct {
	Epoch Epoch
	Hash  []byte
}

func (o *EpochHash) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.Epoch)
	b = marshal.WriteBytes(b, o.Hash)
	return b
}

func (o *EpochHash) Decode(b0 []byte) ([]byte, Error) {
	var b = b0
	epoch, b, err := SafeReadInt(b)
	if err != ErrNone {
		return nil, err
	}
	hash, b, err := SafeReadBytes(b, cryptoShim.HashLen)
	if err != ErrNone {
		return nil, err
	}
	o.Epoch = epoch
	o.Hash = hash
	return b, ErrNone
}

type PutArg struct {
	Id  merkle.Id
	Val merkle.Val
}

func (o *PutArg) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteBytes(b, o.Id)
	b = WriteSlice1D(b, o.Val)
	return b
}

func (o *PutArg) Decode(b0 []byte) ([]byte, Error) {
	var b = b0
	id, b, err := SafeReadBytes(b, cryptoShim.HashLen)
	if err != ErrNone {
		return nil, err
	}
	val, b, err := ReadSlice1D(b)
	if err != ErrNone {
		return nil, err
	}
	o.Id = id
	o.Val = val
	return b, ErrNone
}

type PutReply struct {
	Epoch Epoch
	Error Error
}

func (o *PutReply) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.Epoch)
	b = marshal.WriteInt(b, o.Error)
	return b
}

func (o *PutReply) Decode(b0 []byte) ([]byte, Error) {
	var b = b0
	epoch, b, err := SafeReadInt(b)
	if err != ErrNone {
		return nil, err
	}
	error, b, err := SafeReadInt(b)
	if err != ErrNone {
		return nil, err
	}
	o.Epoch = epoch
	o.Error = error
	return b, ErrNone
}

func CallPut(cli *urpc.Client, id merkle.Id, val merkle.Val) (Epoch, Error) {
	argB := (&PutArg{Id: id, Val: val}).Encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(RpcKeyServPut, argB, &replyB, 100)
	if err0 != ErrNone {
		return 0, err0
	}
	reply := &PutReply{}
	_, err1 := reply.Decode(replyB)
	if err1 != ErrNone {
		return 0, err1
	}
	return reply.Epoch, reply.Error
}

type GetIdAtEpochArg struct {
	Id    merkle.Id
	Epoch Epoch
}

func (o *GetIdAtEpochArg) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteBytes(b, o.Id)
	b = marshal.WriteInt(b, o.Epoch)
	return b
}

func (o *GetIdAtEpochArg) Decode(b0 []byte) ([]byte, Error) {
	var b = b0
	id, b, err := SafeReadBytes(b, cryptoShim.HashLen)
	if err != ErrNone {
		return nil, err
	}
	epoch, b, err := SafeReadInt(b)
	if err != ErrNone {
		return nil, err
	}
	o.Id = id
	o.Epoch = epoch
	return b, ErrNone
}

type GetIdAtEpochReply struct {
	Val     merkle.Val
	Digest  merkle.Digest
	ProofTy merkle.ProofTy
	Proof   merkle.Proof
	Error   Error
}

func (o *GetIdAtEpochReply) Encode() []byte {
	var b = make([]byte, 0)
	b = WriteSlice1D(b, o.Val)
	b = marshal.WriteBytes(b, o.Digest)
	b = WriteBool(b, o.ProofTy)
	b = WriteSlice3D(b, o.Proof)
	b = marshal.WriteInt(b, o.Error)
	return b
}

func (o *GetIdAtEpochReply) Decode(b0 []byte) ([]byte, Error) {
	var b = b0
	val, b, err := ReadSlice1D(b)
	if err != ErrNone {
		return nil, err
	}
	digest, b, err := SafeReadBytes(b, cryptoShim.HashLen)
	if err != ErrNone {
		return nil, err
	}
	proofTy, b, err := ReadBool(b)
	if err != ErrNone {
		return nil, err
	}
	proof, b, err := ReadSlice3D(b)
	if err != ErrNone {
		return nil, err
	}
	error, b, err := SafeReadInt(b)
	if err != ErrNone {
		return nil, err
	}
	o.Val = val
	o.Digest = digest
	o.ProofTy = proofTy
	o.Proof = proof
	o.Error = error
	return b, ErrNone
}

func CallGetIdAtEpoch(cli *urpc.Client, id merkle.Id, epoch Epoch) *GetIdAtEpochReply {
	errReply := &GetIdAtEpochReply{}
	argB := (&GetIdAtEpochArg{Id: id, Epoch: epoch}).Encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(RpcKeyServGetIdAtEpoch, argB, &replyB, 100)
	if err0 != ErrNone {
		errReply.Error = err0
		return errReply
	}
	reply := &GetIdAtEpochReply{}
	_, err1 := reply.Decode(replyB)
	if err1 != ErrNone {
		errReply.Error = err1
		return errReply
	}
	return reply
}

type GetIdLatestArg struct {
	Id merkle.Id
}

func (o *GetIdLatestArg) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteBytes(b, o.Id)
	return b
}

func (o *GetIdLatestArg) Decode(b0 []byte) ([]byte, Error) {
	var b = b0
	id, b, err := SafeReadBytes(b, cryptoShim.HashLen)
	if err != ErrNone {
		return nil, err
	}
	o.Id = id
	return b, ErrNone
}

type GetIdLatestReply struct {
	Epoch   Epoch
	Val     merkle.Val
	Digest  merkle.Digest
	ProofTy merkle.ProofTy
	Proof   merkle.Proof
	Error   Error
}

func (o *GetIdLatestReply) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.Epoch)
	b = WriteSlice1D(b, o.Val)
	b = marshal.WriteBytes(b, o.Digest)
	b = WriteBool(b, o.ProofTy)
	b = WriteSlice3D(b, o.Proof)
	b = marshal.WriteInt(b, o.Error)
	return b
}

func (o *GetIdLatestReply) Decode(b0 []byte) ([]byte, Error) {
	var b = b0
	epoch, b, err := SafeReadInt(b)
	if err != ErrNone {
		return nil, err
	}
	val, b, err := ReadSlice1D(b)
	if err != ErrNone {
		return nil, err
	}
	digest, b, err := SafeReadBytes(b, cryptoShim.HashLen)
	if err != ErrNone {
		return nil, err
	}
	proofTy, b, err := ReadBool(b)
	if err != ErrNone {
		return nil, err
	}
	proof, b, err := ReadSlice3D(b)
	if err != ErrNone {
		return nil, err
	}
	error, b, err := SafeReadInt(b)
	if err != ErrNone {
		return nil, err
	}
	o.Epoch = epoch
	o.Val = val
	o.Digest = digest
	o.ProofTy = proofTy
	o.Proof = proof
	o.Error = error
	return b, ErrNone
}

func CallGetIdLatest(cli *urpc.Client, id merkle.Id) *GetIdLatestReply {
	errReply := &GetIdLatestReply{}
	argB := (&GetIdLatestArg{Id: id}).Encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(RpcKeyServGetIdLatest, argB, &replyB, 100)
	if err0 != ErrNone {
		errReply.Error = err0
		return errReply
	}
	reply := &GetIdLatestReply{}
	_, err1 := reply.Decode(replyB)
	if err1 != ErrNone {
		errReply.Error = err1
		return errReply
	}
	return reply
}

type GetDigestArg struct {
	Epoch Epoch
}

func (o *GetDigestArg) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.Epoch)
	return b
}

func (o *GetDigestArg) Decode(b0 []byte) ([]byte, Error) {
	var b = b0
	epoch, b, err := SafeReadInt(b)
	if err != ErrNone {
		return nil, err
	}
	o.Epoch = epoch
	return b, ErrNone
}

type GetDigestReply struct {
	Digest merkle.Digest
	Error  Error
}

func (o *GetDigestReply) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteBytes(b, o.Digest)
	b = marshal.WriteInt(b, o.Error)
	return b
}

func (o *GetDigestReply) Decode(b0 []byte) ([]byte, Error) {
	var b = b0
	digest, b, err := SafeReadBytes(b, cryptoShim.HashLen)
	if err != ErrNone {
		return nil, err
	}
	error, b, err := SafeReadInt(b)
	if err != ErrNone {
		return nil, err
	}
	o.Digest = digest
	o.Error = error
	return b, ErrNone
}

func CallGetDigest(cli *urpc.Client, epoch Epoch) (merkle.Digest, Error) {
	argB := (&GetDigestArg{Epoch: epoch}).Encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(RpcKeyServGetDigest, argB, &replyB, 100)
	if err0 != ErrNone {
		return nil, err0
	}
	reply := &GetDigestReply{}
	_, err1 := reply.Decode(replyB)
	if err1 != ErrNone {
		return nil, err1
	}
	return reply.Digest, reply.Error
}

type UpdateArg struct {
	Epoch  Epoch
	Digest merkle.Digest
}

func (o *UpdateArg) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.Epoch)
	b = marshal.WriteBytes(b, o.Digest)
	return b
}

func (o *UpdateArg) Decode(b0 []byte) ([]byte, Error) {
	var b = b0
	epoch, b, err := SafeReadInt(b)
	if err != ErrNone {
		return nil, err
	}
	digest, b, err := SafeReadBytes(b, cryptoShim.HashLen)
	if err != ErrNone {
		return nil, err
	}
	o.Epoch = epoch
	o.Digest = digest
	return b, ErrNone
}

type UpdateReply struct {
	Error Error
}

func (o *UpdateReply) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.Error)
	return b
}

func (o *UpdateReply) Decode(b0 []byte) ([]byte, Error) {
	var b = b0
	error, b, err := SafeReadInt(b)
	if err != ErrNone {
		return nil, err
	}
	o.Error = error
	return b, ErrNone
}

func CallUpdate(cli *urpc.Client, epoch Epoch, dig merkle.Digest) Error {
	argB := (&UpdateArg{Epoch: epoch, Digest: dig}).Encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(RpcAuditorUpdate, argB, &replyB, 100)
	if err0 != ErrNone {
		return err0
	}
	reply := &UpdateReply{}
	_, err1 := reply.Decode(replyB)
	if err1 != ErrNone {
		return err1
	}
	return reply.Error
}

type GetLinkArg struct {
	Epoch Epoch
}

func (o *GetLinkArg) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.Epoch)
	return b
}

func (o *GetLinkArg) Decode(b0 []byte) ([]byte, Error) {
	var b = b0
	epoch, b, err := SafeReadInt(b)
	if err != ErrNone {
		return nil, err
	}
	o.Epoch = epoch
	return b, ErrNone
}

type GetLinkReply struct {
	Link  Link
	Sig   cryptoShim.Sig
	Error Error
}

func (o *GetLinkReply) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteBytes(b, o.Link)
	b = marshal.WriteBytes(b, o.Sig)
	b = marshal.WriteInt(b, o.Error)
	return b
}

func (o *GetLinkReply) Decode(b0 []byte) ([]byte, Error) {
	var b = b0
	link, b, err := SafeReadBytes(b, cryptoShim.HashLen)
	if err != ErrNone {
		return nil, err
	}
	sig, b, err := SafeReadBytes(b, cryptoShim.SigLen)
	if err != ErrNone {
		return nil, err
	}
	error, b, err := SafeReadInt(b)
	if err != ErrNone {
		return nil, err
	}
	o.Link = link
	o.Sig = sig
	o.Error = error
	return b, ErrNone
}

func CallGetLink(cli *urpc.Client, epoch Epoch) (Link, cryptoShim.Sig, Error) {
	argB := (&GetLinkArg{Epoch: epoch}).Encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(RpcAuditorGetLink, argB, &replyB, 100)
	if err0 != ErrNone {
		return nil, nil, err0
	}
	reply := &GetLinkReply{}
	_, err1 := reply.Decode(replyB)
	if err1 != ErrNone {
		return nil, nil, err1
	}
	return reply.Link, reply.Sig, reply.Error
}
