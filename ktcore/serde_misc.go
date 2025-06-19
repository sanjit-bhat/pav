package ktcore

import (
	"github.com/mit-pdos/pav/marshalutil"
	"github.com/tchajed/marshal"
)

func UpdateProofSlice1DEncode(b0 []byte, o []*UpdateProof) []byte {
	var b = b0
	b = marshal.WriteInt(b, uint64(len(o)))
	for _, e := range o {
		b = UpdateProofEncode(b, e)
	}
	return b
}

func UpdateProofSlice1DDecode(b0 []byte) ([]*UpdateProof, []byte, bool) {
	length, b1, err1 := marshalutil.ReadInt(b0)
	if err1 {
		return nil, nil, true
	}
	var loopO = make([]*UpdateProof, 0, length)
	var loopErr bool
	var loopB = b1
	for i := uint64(0); i < length; i++ {
		a2, loopB1, err2 := UpdateProofDecode(loopB)
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
