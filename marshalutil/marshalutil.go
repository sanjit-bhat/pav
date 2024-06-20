package marshalutil

import (
	"github.com/tchajed/marshal"
)

type errorTy = bool

const (
	errNone errorTy = false
	errSome errorTy = true
)

func ReadBool(b0 []byte) (bool, []byte, errorTy) {
	var b = b0
	if uint64(len(b)) < 1 {
		return false, nil, errSome
	}
	data, b := marshal.ReadBool(b)
	return data, b, errNone
}

func ReadConstBool(b0 []byte, cst bool) ([]byte, errorTy) {
	var b = b0
	res, b, err := ReadBool(b)
	if err {
		return nil, errSome
	}
	if res != cst {
		return nil, errSome
	}
	return b, errNone
}

func ReadInt(b0 []byte) (uint64, []byte, errorTy) {
	var b = b0
	if uint64(len(b)) < 8 {
		return 0, nil, errSome
	}
	data, b := marshal.ReadInt(b)
	return data, b, errNone
}

func ReadConstInt(b0 []byte, cst uint64) ([]byte, errorTy) {
	var b = b0
	res, b, err := ReadInt(b)
	if err {
		return nil, errSome
	}
	if res != cst {
		return nil, errSome
	}
	return b, errNone
}

func ReadByte(b0 []byte) (byte, []byte, errorTy) {
	var b = b0
	if uint64(len(b)) < 1 {
		return 0, nil, errSome
	}
	data, b := marshal.ReadBytes(b, 1)
	return data[0], b, errNone
}

func ReadConstByte(b0 []byte, cst byte) ([]byte, errorTy) {
	var b = b0
	res, b, err := ReadByte(b)
	if err {
		return nil, errSome
	}
	if res != cst {
		return nil, errSome
	}
	return b, errNone
}

func WriteByte(b0 []byte, data byte) []byte {
	var b = b0
	b = marshal.WriteBytes(b, []byte{data})
	return b
}

func ReadBytes(b0 []byte, length uint64) ([]byte, []byte, errorTy) {
	var b = b0
	if uint64(len(b)) < length {
		return nil, nil, errSome
	}
	data, b := marshal.ReadBytes(b, length)
	return data, b, errNone
}

func ReadSlice1D(b0 []byte) ([]byte, []byte, errorTy) {
	var b = b0
	length, b, err := ReadInt(b)
	if err {
		return nil, nil, err
	}
	data, b, err := ReadBytes(b, length)
	if err {
		return nil, nil, err
	}
	return data, b, errNone
}

func WriteSlice1D(b0 []byte, data []byte) []byte {
	var b = b0
	b = marshal.WriteInt(b, uint64(len(data)))
	b = marshal.WriteBytes(b, data)
	return b
}

func ReadSlice2D(b0 []byte) ([][]byte, []byte, errorTy) {
	var b = b0
	length, b, err := ReadInt(b)
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

func WriteSlice2D(b0 []byte, data [][]byte) []byte {
	var b = b0
	b = marshal.WriteInt(b, uint64(len(data)))
	for _, data1 := range data {
		b = WriteSlice1D(b, data1)
	}
	return b
}

func ReadSlice3D(b0 []byte) ([][][]byte, []byte, errorTy) {
	var b = b0
	length, b, err := ReadInt(b)
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

func WriteSlice3D(b0 []byte, data [][][]byte) []byte {
	var b = b0
	b = marshal.WriteInt(b, uint64(len(data)))
	for _, data1 := range data {
		b = WriteSlice2D(b, data1)
	}
	return b
}
