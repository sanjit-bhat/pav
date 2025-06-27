// Auto-generated from spec "github.com/sanjit-bhat/pav/serde/testdata/alias/alias.go"
// using compiler "github.com/sanjit-bhat/pav/serde".
package serde

import (
	"github.com/sanjit-bhat/pav/marshalutil"
	"github.com/tchajed/marshal"
)

func argEncode(b0 []byte, o *arg) []byte {
	var b = b0
	b = marshal.WriteInt(b, o.x)
	b = marshal.WriteInt(b, o.y)
	return b
}
func argDecode(b0 []byte) (*arg, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadInt(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := marshalutil.ReadInt(b1)
	if err2 {
		return nil, nil, true
	}
	return &arg{x: a1, y: a2}, b2, false
}
