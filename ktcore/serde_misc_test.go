package ktcore

import (
	"testing"

	"github.com/tchajed/marshal"
)

func TestMembSlice1DDecode(t *testing.T) {
	b := marshal.WriteInt(nil, 0x8000000000000000)
	_, _, err := MembSlice1DDecode(b)
	if err {
		t.Errorf("error")
	}
}
