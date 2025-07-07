package safemarshal

import (
	"github.com/tchajed/marshal"
)

// TODO: pre-size byte slices for encoding functions.

func ReadBool(b []byte) (data bool, rem []byte, err bool) {
	rem = b
	if uint64(len(rem)) < 1 {
		err = true
		return
	}
	data, rem = marshal.ReadBool(rem)
	return
}

func ReadConstBool(b []byte, cst bool) (rem []byte, err bool) {
	rem = b
	data, rem, err := ReadBool(rem)
	if err {
		return
	}
	if data != cst {
		err = true
		return
	}
	return
}

func ReadInt(b []byte) (data uint64, rem []byte, err bool) {
	rem = b
	if uint64(len(rem)) < 8 {
		err = true
		return
	}
	data, rem = marshal.ReadInt(rem)
	return
}

func ReadConstInt(b []byte, cst uint64) (rem []byte, err bool) {
	rem = b
	data, rem, err := ReadInt(rem)
	if err {
		return
	}
	if data != cst {
		err = true
		return
	}
	return
}

func ReadByte(b []byte) (data byte, rem []byte, err bool) {
	rem = b
	if uint64(len(rem)) < 1 {
		err = true
		return
	}
	data0, rem := marshal.ReadBytes(rem, 1)
	data = data0[0]
	return
}

func ReadConstByte(b []byte, cst byte) (rem []byte, err bool) {
	rem = b
	data, rem, err := ReadByte(rem)
	if err {
		return
	}
	if data != cst {
		err = true
		return
	}
	return
}

func WriteByte(b []byte, data byte) []byte {
	return marshal.WriteBytes(b, []byte{data})
}

func ReadBytes(b []byte, length uint64) (data []byte, rem []byte, err bool) {
	rem = b
	if uint64(len(rem)) < length {
		err = true
		return
	}
	data, rem = marshal.ReadBytes(rem, length)
	return
}

func ReadSlice1D(b []byte) (data []byte, rem []byte, err bool) {
	rem = b
	length, rem, err := ReadInt(rem)
	if err {
		return
	}
	return ReadBytes(rem, length)
}

func WriteSlice1D(b []byte, data []byte) []byte {
	b = marshal.WriteInt(b, uint64(len(data)))
	return marshal.WriteBytes(b, data)
}

func ReadSlice2D(b []byte) (data [][]byte, rem []byte, err bool) {
	rem = b
	length, rem, err := ReadInt(rem)
	if err {
		return
	}
	for i := uint64(0); i < length; i++ {
		var data0 []byte
		data0, rem, err = ReadSlice1D(rem)
		if err {
			return
		}
		data = append(data, data0)
	}
	return
}

func WriteSlice2D(b []byte, data [][]byte) []byte {
	b = marshal.WriteInt(b, uint64(len(data)))
	for _, data1 := range data {
		b = WriteSlice1D(b, data1)
	}
	return b
}

func ReadSlice3D(b []byte) (data [][][]byte, rem []byte, err bool) {
	rem = b
	length, rem, err := ReadInt(rem)
	if err {
		return
	}
	for i := uint64(0); i < length; i++ {
		var data0 [][]byte
		data0, rem, err = ReadSlice2D(rem)
		if err {
			return
		}
		data = append(data, data0)
	}
	return
}

func WriteSlice3D(b []byte, data [][][]byte) []byte {
	b = marshal.WriteInt(b, uint64(len(data)))
	for _, data1 := range data {
		b = WriteSlice2D(b, data1)
	}
	return b
}
