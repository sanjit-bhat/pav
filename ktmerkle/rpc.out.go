// Auto-generated from spec "github.com/mit-pdos/pav/ktmerkle/newrpc.go"
// using compiler "github.com/mit-pdos/pav/rpc".
package ktmerkle

import (
	"github.com/mit-pdos/pav/marshalutil"
	"github.com/tchajed/marshal"
)

func (o *epochHash) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.epoch)
	b = marshalutil.WriteSlice1D(b, o.hash)
	return b
}
func (o *epochHash) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	epoch, b, err := marshalutil.SafeReadInt(b)
	if err {
		return nil, err
	}
	hash, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	o.epoch = epoch
	o.hash = hash
	return b, errNone
}
func (o *putArg) encode() []byte {
	var b = make([]byte, 0)
	b = marshalutil.WriteSlice1D(b, o.id)
	b = marshalutil.WriteSlice1D(b, o.val)
	return b
}
func (o *putArg) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	id, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	val, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	o.id = id
	o.val = val
	return b, errNone
}
func (o *idValEpoch) encode() []byte {
	var b = make([]byte, 0)
	b = marshalutil.WriteSlice1D(b, o.id)
	b = marshalutil.WriteSlice1D(b, o.val)
	b = marshal.WriteInt(b, o.epoch)
	return b
}
func (o *idValEpoch) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	id, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	val, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	epoch, b, err := marshalutil.SafeReadInt(b)
	if err {
		return nil, err
	}
	o.id = id
	o.val = val
	o.epoch = epoch
	return b, errNone
}
func (o *putReply) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.epoch)
	b = marshalutil.WriteSlice1D(b, o.sig)
	b = marshalutil.WriteBool(b, o.error)
	return b
}
func (o *putReply) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	epoch, b, err := marshalutil.SafeReadInt(b)
	if err {
		return nil, err
	}
	sig, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	error, b, err := marshalutil.ReadBool(b)
	if err {
		return nil, err
	}
	o.epoch = epoch
	o.sig = sig
	o.error = error
	return b, errNone
}
func (o *getIdAtEpochArg) encode() []byte {
	var b = make([]byte, 0)
	b = marshalutil.WriteSlice1D(b, o.id)
	b = marshal.WriteInt(b, o.epoch)
	return b
}
func (o *getIdAtEpochArg) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	id, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	epoch, b, err := marshalutil.SafeReadInt(b)
	if err {
		return nil, err
	}
	o.id = id
	o.epoch = epoch
	return b, errNone
}
func (o *getIdAtEpochReply) encode() []byte {
	var b = make([]byte, 0)
	b = marshalutil.WriteSlice1D(b, o.val)
	b = marshalutil.WriteSlice1D(b, o.digest)
	b = marshalutil.WriteBool(b, o.proofTy)
	b = marshalutil.WriteSlice3D(b, o.proof)
	b = marshalutil.WriteSlice1D(b, o.sig)
	b = marshalutil.WriteBool(b, o.error)
	return b
}
func (o *getIdAtEpochReply) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	val, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	digest, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	proofTy, b, err := marshalutil.ReadBool(b)
	if err {
		return nil, err
	}
	proof, b, err := marshalutil.ReadSlice3D(b)
	if err {
		return nil, err
	}
	sig, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	error, b, err := marshalutil.ReadBool(b)
	if err {
		return nil, err
	}
	o.val = val
	o.digest = digest
	o.proofTy = proofTy
	o.proof = proof
	o.sig = sig
	o.error = error
	return b, errNone
}
func (o *getIdLatestArg) encode() []byte {
	var b = make([]byte, 0)
	b = marshalutil.WriteSlice1D(b, o.id)
	return b
}
func (o *getIdLatestArg) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	id, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	o.id = id
	return b, errNone
}
func (o *getIdLatestReply) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.epoch)
	b = marshalutil.WriteSlice1D(b, o.val)
	b = marshalutil.WriteSlice1D(b, o.digest)
	b = marshalutil.WriteBool(b, o.proofTy)
	b = marshalutil.WriteSlice3D(b, o.proof)
	b = marshalutil.WriteSlice1D(b, o.sig)
	b = marshalutil.WriteBool(b, o.error)
	return b
}
func (o *getIdLatestReply) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	epoch, b, err := marshalutil.SafeReadInt(b)
	if err {
		return nil, err
	}
	val, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	digest, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	proofTy, b, err := marshalutil.ReadBool(b)
	if err {
		return nil, err
	}
	proof, b, err := marshalutil.ReadSlice3D(b)
	if err {
		return nil, err
	}
	sig, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	error, b, err := marshalutil.ReadBool(b)
	if err {
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
func (o *getDigestArg) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.epoch)
	return b
}
func (o *getDigestArg) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	epoch, b, err := marshalutil.SafeReadInt(b)
	if err {
		return nil, err
	}
	o.epoch = epoch
	return b, errNone
}
func (o *getDigestReply) encode() []byte {
	var b = make([]byte, 0)
	b = marshalutil.WriteSlice1D(b, o.digest)
	b = marshalutil.WriteSlice1D(b, o.sig)
	b = marshalutil.WriteBool(b, o.error)
	return b
}
func (o *getDigestReply) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	digest, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	sig, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	error, b, err := marshalutil.ReadBool(b)
	if err {
		return nil, err
	}
	o.digest = digest
	o.sig = sig
	o.error = error
	return b, errNone
}
func (o *updateArg) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.epoch)
	b = marshalutil.WriteSlice1D(b, o.digest)
	b = marshalutil.WriteSlice1D(b, o.sig)
	return b
}
func (o *updateArg) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	epoch, b, err := marshalutil.SafeReadInt(b)
	if err {
		return nil, err
	}
	digest, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	sig, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	o.epoch = epoch
	o.digest = digest
	o.sig = sig
	return b, errNone
}
func (o *updateReply) encode() []byte {
	var b = make([]byte, 0)
	b = marshalutil.WriteBool(b, o.error)
	return b
}
func (o *updateReply) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	error, b, err := marshalutil.ReadBool(b)
	if err {
		return nil, err
	}
	o.error = error
	return b, errNone
}
func (o *getLinkArg) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.epoch)
	return b
}
func (o *getLinkArg) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	epoch, b, err := marshalutil.SafeReadInt(b)
	if err {
		return nil, err
	}
	o.epoch = epoch
	return b, errNone
}
func (o *getLinkReply) encode() []byte {
	var b = make([]byte, 0)
	b = marshalutil.WriteSlice1D(b, o.link)
	b = marshalutil.WriteSlice1D(b, o.sig)
	b = marshalutil.WriteBool(b, o.error)
	return b
}
func (o *getLinkReply) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	link, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	sig, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	error, b, err := marshalutil.ReadBool(b)
	if err {
		return nil, err
	}
	o.link = link
	o.sig = sig
	o.error = error
	return b, errNone
}
