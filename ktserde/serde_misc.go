package ktserde

import (
	"github.com/mit-pdos/pav/marshalutil"
	"github.com/tchajed/marshal"
)

func MembSlice1DEncode(b0 []byte, o []*Memb) []byte {
	var b = b0
	b = marshal.WriteInt(b, uint64(len(o)))
	for _, e := range o {
		b = MembEncode(b, e)
	}
	return b
}

func MembSlice1DDecode(b0 []byte) ([]*Memb, []byte, bool) {
	length, b1, err1 := marshalutil.ReadInt(b0)
	if err1 {
		return nil, nil, true
	}
	var loopO = make([]*Memb, 0, length)
	var loopErr bool
	var loopB = b1
	for i := uint64(0); i < length; i++ {
		a2, loopB1, err2 := MembDecode(loopB)
		loopB = loopB1
		if err2 {
			loopErr = true
			break
		}
		loopO = append(loopO, a2)
	}
	if loopErr {
		return nil, nil, true
	}
	return loopO, loopB, false
}

func MapstringSlbyteEncode(b0 []byte, o map[string][]byte) []byte {
	var b = b0
	b = marshal.WriteInt(b, uint64(len(o)))
	for k, v := range o {
		b = marshalutil.WriteSlice1D(b, []byte(k))
		b = marshalutil.WriteSlice1D(b, v)
	}
	return b
}

func MapstringSlbyteDecode(b0 []byte) (map[string][]byte, []byte, bool) {
	length, b1, err1 := marshalutil.ReadInt(b0)
	if err1 {
		return nil, nil, true
	}
	loopO := make(map[string][]byte, length)
	var loopErr bool
	var loopB = b1
	for i := uint64(0); i < length; i++ {
		a2, loopB1, err2 := marshalutil.ReadSlice1D(loopB)
		loopB = loopB1
		if err2 {
			loopErr = true
			break
		}
		a3, loopB2, err3 := marshalutil.ReadSlice1D(loopB)
		loopB = loopB2
		if err3 {
			loopErr = true
			break
		}
		loopO[string(a2)] = a3
	}
	if loopErr {
		return nil, nil, true
	}
	return loopO, loopB, false
}
