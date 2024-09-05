// Auto-generated from spec "github.com/mit-pdos/pav/kt/rpc.go"
// using compiler "github.com/mit-pdos/pav/rpc".
package kt

import (
	"github.com/mit-pdos/pav/marshalutil"
	"github.com/tchajed/marshal"
)

func (o *chainSepNone) encode() []byte {
	var b = make([]byte, 0)
	b = marshalutil.WriteByte(b, 0)
	return b
}
func (o *chainSepSome) encode() []byte {
	var b = make([]byte, 0)
	b = marshalutil.WriteByte(b, 1)
	b = marshal.WriteInt(b, o.epoch)
	b = marshalutil.WriteSlice1D(b, o.prevLink)
	b = marshalutil.WriteSlice1D(b, o.data)
	return b
}
func (o *adtrSepLink) encode() []byte {
	var b = make([]byte, 0)
	b = marshalutil.WriteByte(b, 0)
	b = marshalutil.WriteSlice1D(b, o.link)
	return b
}
func (o *servSepLink) encode() []byte {
	var b = make([]byte, 0)
	b = marshalutil.WriteByte(b, 0)
	b = marshalutil.WriteSlice1D(b, o.link)
	return b
}
func (o *servSepPut) encode() []byte {
	var b = make([]byte, 0)
	b = marshalutil.WriteByte(b, 1)
	b = marshal.WriteInt(b, o.epoch)
	b = marshalutil.WriteSlice1D(b, o.id)
	b = marshalutil.WriteSlice1D(b, o.val)
	return b
}
func (o *servPutArg) encode() []byte {
	var b = make([]byte, 0)
	b = marshalutil.WriteSlice1D(b, o.id)
	b = marshalutil.WriteSlice1D(b, o.val)
	return b
}
func (o *servPutArg) decode(b0 []byte) ([]byte, errorTy) {
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
func (o *servPutReply) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.putEpoch)
	b = marshalutil.WriteSlice1D(b, o.prevLink)
	b = marshalutil.WriteSlice1D(b, o.dig)
	b = marshalutil.WriteSlice1D(b, o.linkSig)
	b = marshalutil.WriteSlice1D(b, o.putSig)
	b = marshal.WriteBool(b, o.error)
	return b
}
func (o *servPutReply) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	putEpoch, b, err := marshalutil.ReadInt(b)
	if err {
		return nil, err
	}
	prevLink, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	dig, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	linkSig, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	putSig, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	error, b, err := marshalutil.ReadBool(b)
	if err {
		return nil, err
	}
	o.putEpoch = putEpoch
	o.prevLink = prevLink
	o.dig = dig
	o.linkSig = linkSig
	o.putSig = putSig
	o.error = error
	return b, errNone
}
func (o *servGetIdAtArg) encode() []byte {
	var b = make([]byte, 0)
	b = marshalutil.WriteSlice1D(b, o.id)
	b = marshal.WriteInt(b, o.epoch)
	return b
}
func (o *servGetIdAtArg) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	id, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	epoch, b, err := marshalutil.ReadInt(b)
	if err {
		return nil, err
	}
	o.id = id
	o.epoch = epoch
	return b, errNone
}
func (o *servGetIdAtReply) encode() []byte {
	var b = make([]byte, 0)
	b = marshalutil.WriteSlice1D(b, o.prevLink)
	b = marshalutil.WriteSlice1D(b, o.dig)
	b = marshalutil.WriteSlice1D(b, o.sig)
	b = marshalutil.WriteSlice1D(b, o.val)
	b = marshal.WriteBool(b, o.proofTy)
	b = marshalutil.WriteSlice3D(b, o.proof)
	b = marshal.WriteBool(b, o.error)
	return b
}
func (o *servGetIdAtReply) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	prevLink, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	dig, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	sig, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	val, b, err := marshalutil.ReadSlice1D(b)
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
	error, b, err := marshalutil.ReadBool(b)
	if err {
		return nil, err
	}
	o.prevLink = prevLink
	o.dig = dig
	o.sig = sig
	o.val = val
	o.proofTy = proofTy
	o.proof = proof
	o.error = error
	return b, errNone
}
func (o *servGetLinkArg) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.epoch)
	return b
}
func (o *servGetLinkArg) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	epoch, b, err := marshalutil.ReadInt(b)
	if err {
		return nil, err
	}
	o.epoch = epoch
	return b, errNone
}
func (o *servGetLinkReply) encode() []byte {
	var b = make([]byte, 0)
	b = marshalutil.WriteSlice1D(b, o.prevLink)
	b = marshalutil.WriteSlice1D(b, o.dig)
	b = marshalutil.WriteSlice1D(b, o.sig)
	b = marshal.WriteBool(b, o.error)
	return b
}
func (o *servGetLinkReply) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	prevLink, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	dig, b, err := marshalutil.ReadSlice1D(b)
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
	o.prevLink = prevLink
	o.dig = dig
	o.sig = sig
	o.error = error
	return b, errNone
}
func (o *adtrPutArg) encode() []byte {
	var b = make([]byte, 0)
	b = marshalutil.WriteSlice1D(b, o.prevLink)
	b = marshalutil.WriteSlice1D(b, o.dig)
	b = marshalutil.WriteSlice1D(b, o.servSig)
	return b
}
func (o *adtrPutArg) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	prevLink, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	dig, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	servSig, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	o.prevLink = prevLink
	o.dig = dig
	o.servSig = servSig
	return b, errNone
}
func (o *adtrPutReply) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteBool(b, o.error)
	return b
}
func (o *adtrPutReply) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	error, b, err := marshalutil.ReadBool(b)
	if err {
		return nil, err
	}
	o.error = error
	return b, errNone
}
func (o *adtrGetArg) encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, o.epoch)
	return b
}
func (o *adtrGetArg) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	epoch, b, err := marshalutil.ReadInt(b)
	if err {
		return nil, err
	}
	o.epoch = epoch
	return b, errNone
}
func (o *adtrGetReply) encode() []byte {
	var b = make([]byte, 0)
	b = marshalutil.WriteSlice1D(b, o.prevLink)
	b = marshalutil.WriteSlice1D(b, o.dig)
	b = marshalutil.WriteSlice1D(b, o.servSig)
	b = marshalutil.WriteSlice1D(b, o.adtrSig)
	b = marshal.WriteBool(b, o.error)
	return b
}
func (o *adtrGetReply) decode(b0 []byte) ([]byte, errorTy) {
	var b = b0
	prevLink, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	dig, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	servSig, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	adtrSig, b, err := marshalutil.ReadSlice1D(b)
	if err {
		return nil, err
	}
	error, b, err := marshalutil.ReadBool(b)
	if err {
		return nil, err
	}
	o.prevLink = prevLink
	o.dig = dig
	o.servSig = servSig
	o.adtrSig = adtrSig
	o.error = error
	return b, errNone
}
