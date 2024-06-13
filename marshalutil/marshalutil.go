package marshalutil

import (
	"github.com/tchajed/marshal"
)

type errorTy = bool

const (
	errNone errorTy = false
	errSome errorTy = true
)

func ReadConstInt(b0 []byte, cst uint64) ([]byte, errorTy) {
	var b = b0
	if uint64(len(b0)) < 8 {
		return nil, errSome
	}
	data, b := marshal.ReadInt(b)
	if data != cst {
		return nil, errSome
	}
	return b, errNone
}

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
	if err {
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
	if err {
		return nil, nil, err
	}
	data, b, err := SafeReadBytes(b, length)
	if err {
		return nil, nil, err
	}
	return data, b, errNone
}

func ReadSlice2D(b0 []byte) ([][]byte, []byte, errorTy) {
	var b = b0
	length, b, err := SafeReadInt(b)
	if err {
		return nil, nil, err
	}
	var data0 [][]byte
	var err0 errorTy
	var i uint64
	for ; i < length; i++ {
		var data1 []byte
		var err1 errorTy
		data1, b, err1 = ReadSlice1D(b)
		if err1 {
			err0 = err1
			continue
		}
		data0 = append(data0, data1)
	}
	if err0 {
		return nil, nil, err0
	}
	return data0, b, errNone
}

func ReadSlice3D(b0 []byte) ([][][]byte, []byte, errorTy) {
	var b = b0
	length, b, err := SafeReadInt(b)
	if err {
		return nil, nil, err
	}
	var data0 [][][]byte
	var err0 errorTy
	var i uint64
	for ; i < length; i++ {
		var data1 [][]byte
		var err1 errorTy
		data1, b, err1 = ReadSlice2D(b)
		if err1 {
			err0 = err1
			continue
		}
		data0 = append(data0, data1)
	}
	if err0 {
		return nil, nil, err0
	}
	return data0, b, errNone
}
