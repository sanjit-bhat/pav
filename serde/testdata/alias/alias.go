package serde

import (
	"github.com/mit-pdos/pav/serde/testdata/alias/other"
)

type arg struct {
	x other.AliasInt
	y other.DefInt
}
