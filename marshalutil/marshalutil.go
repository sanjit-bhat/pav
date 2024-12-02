package marshalutil

import (
	"github.com/tchajed/marshal"
)

func WriteBytes2D(b0 []byte, data [][]byte) []byte {
	var b = b0
	for _, x := range data {
		b = marshal.WriteBytes(b, x)
	}
	return b
}

func ReadBool(b0 []byte) (bool, []byte, bool) {
	var b = b0
	if uint64(len(b)) < 1 {
		return false, nil, true
	}
	data, b := marshal.ReadBool(b)
	return data, b, false
}

func ReadConstBool(b0 []byte, cst bool) ([]byte, bool) {
	var b = b0
	res, b, err := ReadBool(b)
	if err {
		return nil, true
	}
	if res != cst {
		return nil, true
	}
	return b, false
}

func ReadInt(b0 []byte) (uint64, []byte, bool) {
	var b = b0
	if uint64(len(b)) < 8 {
		return 0, nil, true
	}
	data, b := marshal.ReadInt(b)
	return data, b, false
}

func ReadConstInt(b0 []byte, cst uint64) ([]byte, bool) {
	var b = b0
	res, b, err := ReadInt(b)
	if err {
		return nil, true
	}
	if res != cst {
		return nil, true
	}
	return b, false
}

func ReadByte(b0 []byte) (byte, []byte, bool) {
	var b = b0
	if uint64(len(b)) < 1 {
		return 0, nil, true
	}
	data, b := marshal.ReadBytes(b, 1)
	return data[0], b, false
}

func ReadConstByte(b0 []byte, cst byte) ([]byte, bool) {
	var b = b0
	res, b, err := ReadByte(b)
	if err {
		return nil, true
	}
	if res != cst {
		return nil, true
	}
	return b, false
}

func WriteByte(b0 []byte, data byte) []byte {
	var b = b0
	b = marshal.WriteBytes(b, []byte{data})
	return b
}

func ReadBytes(b0 []byte, length uint64) ([]byte, []byte, bool) {
	var b = b0
	if uint64(len(b)) < length {
		return nil, nil, true
	}
	data, b := marshal.ReadBytes(b, length)
	return data, b, false
}

func ReadSlice1D(b0 []byte) ([]byte, []byte, bool) {
	var b = b0
	length, b, err := ReadInt(b)
	if err {
		return nil, nil, err
	}
	data, b, err := ReadBytes(b, length)
	if err {
		return nil, nil, err
	}
	return data, b, false
}

func WriteSlice1D(b0 []byte, data []byte) []byte {
	var b = b0
	b = marshal.WriteInt(b, uint64(len(data)))
	b = marshal.WriteBytes(b, data)
	return b
}

func ReadSlice2D(b0 []byte) ([][]byte, []byte, bool) {
	var b = b0
	length, b, err := ReadInt(b)
	if err {
		return nil, nil, err
	}
	var data0 [][]byte
	var err0 bool
	var i uint64
	for ; i < length; i++ {
		var data1 []byte
		var err1 bool
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
	return data0, b, false
}

func WriteSlice2D(b0 []byte, data [][]byte) []byte {
	var b = b0
	b = marshal.WriteInt(b, uint64(len(data)))
	for _, data1 := range data {
		b = WriteSlice1D(b, data1)
	}
	return b
}

func ReadSlice3D(b0 []byte) ([][][]byte, []byte, bool) {
	var b = b0
	length, b, err := ReadInt(b)
	if err {
		return nil, nil, err
	}
	var data0 [][][]byte
	var err0 bool
	var i uint64
	for ; i < length; i++ {
		var data1 [][]byte
		var err1 bool
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
	return data0, b, false
}

func WriteSlice3D(b0 []byte, data [][][]byte) []byte {
	var b = b0
	b = marshal.WriteInt(b, uint64(len(data)))
	for _, data1 := range data {
		b = WriteSlice2D(b, data1)
	}
	return b
}
