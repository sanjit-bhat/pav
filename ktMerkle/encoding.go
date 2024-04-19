package ktMerkle

import (
	"github.com/mit-pdos/secure-chat/crypto/shim"
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
	RpcKeyServUpdateEpoch  = 1
	RpcKeyServPut          = 2
	RpcKeyServGetIdAtEpoch = 3
	RpcKeyServGetIdLatest  = 4
	RpcKeyServGetDigest    = 5
	RpcAuditorUpdate       = 1
	RpcAuditorGetLink      = 2
)

func CopySlice(b1 []byte) []byte {
	b2 := make([]byte, len(b1))
	copy(b2, b1)
	return b2
}

func SafeReadInt(b []byte) (uint64, []byte, Error) {
	if uint64(len(b)) < 8 {
		return 0, nil, ErrSome
	}
	data, b := marshal.ReadInt(b)
	return data, b, ErrNone
}

func SafeReadBytes(b []byte, length uint64) ([]byte, []byte, Error) {
	if uint64(len(b)) < length {
		return nil, nil, ErrSome
	}
	data, b := marshal.ReadBytes(b, length)
	return data, b, ErrNone
}

func WriteBool(b []byte, data bool) []byte {
	var data1 uint64
	if data {
		data1 = 1
	}
	b = marshal.WriteInt(b, data1)
	return b
}

func ReadBool(b []byte) (bool, []byte, Error) {
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

func WriteSlice1D(b []byte, data []byte) []byte {
	b = marshal.WriteInt(b, uint64(len(data)))
	b = marshal.WriteBytes(b, data)
	return b
}

func WriteSlice2D(b []byte, data [][]byte) []byte {
	b = marshal.WriteInt(b, uint64(len(data)))
	for _, data1 := range data {
		b = WriteSlice1D(b, data1)
	}
	return b
}

func WriteSlice3D(b []byte, data [][][]byte) []byte {
	b = marshal.WriteInt(b, uint64(len(data)))
	for _, data1 := range data {
		b = WriteSlice2D(b, data1)
	}
	return b
}

func ReadSlice1D(b []byte) ([]byte, []byte, Error) {
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

func ReadSlice2D(b []byte) ([][]byte, []byte, Error) {
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

func ReadSlice3D(b []byte) ([][][]byte, []byte, Error) {
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

func (o *EpochHash) Decode(b []byte) ([]byte, Error) {
	epoch, b, err := SafeReadInt(b)
	if err != ErrNone {
		return nil, err
	}
	hash, b, err := SafeReadBytes(b, shim.HashLen)
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

func (o *PutArg) Decode(b []byte) ([]byte, Error) {
	id, b, err := SafeReadBytes(b, shim.HashLen)
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

func (o *PutReply) Decode(b []byte) ([]byte, Error) {
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

func (o *GetIdAtEpochArg) Decode(b []byte) ([]byte, Error) {
	id, b, err := SafeReadBytes(b, shim.HashLen)
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
	Val     []byte
	Digest  []byte
	ProofTy bool
	Proof   merkle.GenProof
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

func (o *GetIdAtEpochReply) Decode(b []byte) ([]byte, Error) {
	val, b, err := ReadSlice1D(b)
	if err != ErrNone {
		return nil, err
	}
	digest, b, err := SafeReadBytes(b, shim.HashLen)
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

type GetIdLatestArg struct {
	Id merkle.Id
}

func (o *GetIdLatestArg) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteBytes(b, o.Id)
	return b
}

func (o *GetIdLatestArg) Decode(b []byte) ([]byte, Error) {
	id, b, err := SafeReadBytes(b, shim.HashLen)
	if err != ErrNone {
		return nil, err
	}
	o.Id = id
	return b, ErrNone
}

type GetIdLatestReply struct {
	Epoch   Epoch
	Val     []byte
	Digest  []byte
	ProofTy bool
	Proof   merkle.GenProof
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

func (o *GetIdLatestReply) Decode(b []byte) ([]byte, Error) {
	epoch, b, err := SafeReadInt(b)
	if err != ErrNone {
		return nil, err
	}
	val, b, err := ReadSlice1D(b)
	if err != ErrNone {
		return nil, err
	}
	digest, b, err := SafeReadBytes(b, shim.HashLen)
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

type GetDigestArg struct {
	Epoch Epoch
}

func (o *GetDigestArg) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.Epoch)
	return b
}

func (o *GetDigestArg) Decode(b []byte) ([]byte, Error) {
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

func (o *GetDigestReply) Decode(b []byte) ([]byte, Error) {
	digest, b, err := SafeReadBytes(b, shim.HashLen)
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

type UpdateArg struct {
	Digest merkle.Digest
}

func (o *UpdateArg) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteBytes(b, o.Digest)
	return b
}

func (o *UpdateArg) Decode(b []byte) ([]byte, Error) {
	digest, b, err := SafeReadBytes(b, shim.HashLen)
	if err != ErrNone {
		return nil, err
	}
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

func (o *UpdateReply) Decode(b []byte) ([]byte, Error) {
	error, b, err := SafeReadInt(b)
	if err != ErrNone {
		return nil, err
	}
	o.Error = error
	return b, ErrNone
}

type GetLinkArg struct {
	Epoch Epoch
}

func (o *GetLinkArg) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.Epoch)
	return b
}

func (o *GetLinkArg) Decode(b []byte) ([]byte, Error) {
	epoch, b, err := SafeReadInt(b)
	if err != ErrNone {
		return nil, err
	}
	o.Epoch = epoch
	return b, ErrNone
}

type GetLinkReply struct {
	Link  Link
	Sig   shim.Sig
	Error Error
}

func (o *GetLinkReply) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteBytes(b, o.Link)
	b = marshal.WriteBytes(b, o.Sig)
	b = marshal.WriteInt(b, o.Error)
	return b
}

func (o *GetLinkReply) Decode(b []byte) ([]byte, Error) {
	link, b, err := SafeReadBytes(b, shim.HashLen)
	if err != ErrNone {
		return nil, err
	}
	sig, b, err := SafeReadBytes(b, shim.SigLen)
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
