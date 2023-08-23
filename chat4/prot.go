package chat4

import "sync"

type errorT = bool

const (
	ERRNONE bool = false
	ERRSOME bool = true
)

func aliceMain(skAlice *signerT, vkBob *verifierT) (uint64, errorT) {
	// Event 1.
	tag1 := uint64(1)
	body1 := uint64(3948)
	pin1Empt := uint64(0)
	msg1 := newMsgT(tag1, body1, pin1Empt)
	msg1B := encodeMsgT(msg1)
	sig1, err1 := skAlice.sign(msg1B) 
	if err1 {
		return 0, err1
	}
	sn1Scratch := uint64(0)
	msgWrap1 := newMsgWrapT(msg1, sig1, sn1Scratch)
	msgWrap1B := encodeMsgWrapT(msgWrap1) 
	ret1Empt := make([]byte, 0)
	rpcCall(RPCPUT, msgWrap1B, ret1Empt)

	// Event 2.1.
	args2Empt := make([]byte, 0)
	msgWrap2B := newMsgWrapTSlice()
	rpcCall(RPCGET, args2Empt, msgWrap2B)
	msgWrap2, _ := decodeMsgWrapT(msgWrap2B)

	// Event 4.
	args3Empt := make([]byte, 0)
	msgWrap3B := newMsgWrapTSlice()
	rpcCall(RPCGET, args3Empt, msgWrap3B)
	msgWrap3, _ := decodeMsgWrapT(msgWrap3B)
	msg3B := encodeMsgT(msgWrap3.msg)
	ok := vkBob.verify(msg3B, msgWrap3.sig)
	if !ok {
		return 0, ERRSOME
	}

	// Event 5.
	if msgWrap2.sn != msgWrap3.msg.pin {
		return 0, ERRSOME
	}

	return msgWrap2.sn, ERRNONE
}

func bobMain(skBob *signerT, vkAlice *verifierT) (uint64, errorT) {
	// Event 2.2.
	args1Empt := make([]byte, 0)
	msgWrap1B := newMsgWrapTSlice()
	rpcCall(RPCGET, args1Empt, msgWrap1B)
	msgWrap1, _ := decodeMsgWrapT(msgWrap1B)
	msg1B := encodeMsgT(msgWrap1.msg)
	ok := vkAlice.verify(msg1B, msgWrap1.sig)
	if !ok {
		return 0, ERRSOME
	}

	// Event 3.
	tag2 := uint64(2)
	body2 := uint64(8959)
	// Core protocol: msg1's sn becomes pin for msg2.
	msg2 := newMsgT(tag2, body2, msgWrap1.sn)
	msg2B := encodeMsgT(msg2)
	sig2, err2 := skBob.sign(msg2B)
	if err2 {
		return 0, err2
	}
	sn2Scratch := uint64(0)
	msgWrap2 := newMsgWrapT(msg2, sig2, sn2Scratch)
	msgWrap2B := encodeMsgWrapT(msgWrap2)
	ret2Empt := make([]byte, 0)
	rpcCall(RPCPUT, msgWrap2B, ret2Empt)

	return msgWrap1.sn, ERRNONE
}

//lint:ignore U1000 we probably won't verify this.
func setup() {
	skAlice, vkAlice := makeKeys()
	skBob, vkBob := makeKeys()
	wg := new(sync.WaitGroup)
	wg.Add(2)
	go func() {
		aliceMain(skAlice, vkBob)
		wg.Done()
	}()
	go func() {
		bobMain(skBob, vkAlice)
		wg.Done()
	}()
	wg.Wait()
}
