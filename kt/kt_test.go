package kt

import (
	"github.com/mit-pdos/gokv/grove_ffi"
	"testing"
)

func TestAuditPass(t *testing.T) {
	servAddr := grove_ffi.MakeAddress("0.0.0.0:6060")
	audAddr1 := grove_ffi.MakeAddress("0.0.0.0:6061")
	audAddr2 := grove_ffi.MakeAddress("0.0.0.0:6062")
	audAddr3 := grove_ffi.MakeAddress("0.0.0.0:6063")
	audAddrs := []grove_ffi.Address{audAddr1, audAddr2, audAddr3}
	testAuditPass(servAddr, audAddrs)
}

func TestAuditFail(t *testing.T) {
	servAddr1 := grove_ffi.MakeAddress("0.0.0.0:6060")
	servAddr2 := grove_ffi.MakeAddress("0.0.0.0:6061")
	audAddr := grove_ffi.MakeAddress("0.0.0.0:6062")
	testAuditFail(servAddr1, servAddr2, audAddr)
}
