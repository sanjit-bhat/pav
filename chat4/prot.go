package chat4

type errorT = bool

const (
	ERRNONE bool = false
	ERRSOME bool = true
)

type protRet struct {
	err errorT
	sn1 uint64
}

//lint:ignore U1000 top level of verif unit.
func aliceMain() protRet {
	// Event 1.
	body1 := uint64(3948)
	sn1Scratch := uint64(0)
	pin1Empt := uint64(0)
	msg1 := newMsgT(body1, sn1Scratch, pin1Empt)
	msg1B := encodeMsgT(msg1)
	ret1Empt := make([]byte, 0)
	rpcCall(RPCPUT, msg1B, ret1Empt)

	// Event 2.1.
	args2Empt := make([]byte, 0)
	msg1BRet := newMsgTSlice()
	rpcCall(RPCGET, args2Empt, msg1BRet)
	msg1Ret := decodeMsgT(msg1BRet)

	// Event 4.
	args3Empt := make([]byte, 0)
	msg2B := newMsgTSlice()
	rpcCall(RPCGET, args3Empt, msg2B)
	msg2 := decodeMsgT(msg2B)

	// Event 5.
	if msg1Ret.sn != msg2.pin {
		return protRet{err: ERRSOME, sn1: 0}
	}

	return protRet{err: ERRNONE, sn1: msg1Ret.sn}
}

//lint:ignore U1000 top level of verif unit.
func bobMain() protRet {
	// Event 2.2.
	args1Empt := make([]byte, 0)
	msg1B := newMsgTSlice()
	rpcCall(RPCGET, args1Empt, msg1B)
	msg1 := decodeMsgT(msg1B)

	// Event 3.
	body2 := uint64(8959)
	sn2Scratch := uint64(0)
	// Core protocol: msg1's sn becomes pin for msg2.
	msg2 := newMsgT(body2, sn2Scratch, msg1.sn)
	msg2B := encodeMsgT(msg2)
	ret2Empt := make([]byte, 0)
	rpcCall(RPCPUT, msg2B, ret2Empt)

	return protRet{err: ERRNONE, sn1: msg1.sn}
}
