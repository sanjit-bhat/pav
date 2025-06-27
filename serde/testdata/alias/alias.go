package serde

import (
	"github.com/sanjit-bhat/pav/serde/testdata/alias/other"
)

type arg struct {
	x other.AliasInt
	y other.DefInt
}
