package chat4

import "sync"

func aliceMain(skAlice *signerT, vkBob []byte) (uint64, errorT) {
	// Event 1.
	tag1 := uint64(1)
	body1 := uint64(3948)
	pin1Empt := uint64(0)
	msg1 := newMsgT(tag1, body1, pin1Empt)
	msg1B := encodeMsgT(msg1)
	sig1 := skAlice.sign(msg1B)
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
	err3 := verify(vkBob, msg3B, msgWrap3.sig)
	if err3 {
		return 0, err3
	}

	// Event 5.
	if msgWrap2.sn != msgWrap3.msg.pin {
		return 0, ERRSOME
	}

	return msgWrap2.sn, ERRNONE
}

func bobMain(skBob *signerT, vkAlice []byte) (uint64, errorT) {
	// Event 2.2.
	args1Empt := make([]byte, 0)
	msgWrap1B := newMsgWrapTSlice()
	rpcCall(RPCGET, args1Empt, msgWrap1B)
	msgWrap1, _ := decodeMsgWrapT(msgWrap1B)
	msg1B := encodeMsgT(msgWrap1.msg)
	err1 := verify(vkAlice, msg1B, msgWrap1.sig)
	if err1 {
		return 0, err1
	}

	// Event 3.
	tag2 := uint64(2)
	body2 := uint64(8959)
	// Core protocol: msg1's sn becomes pin for msg2.
	msg2 := newMsgT(tag2, body2, msgWrap1.sn)
	msg2B := encodeMsgT(msg2)
	sig2 := skBob.sign(msg2B)
	sn2Scratch := uint64(0)
	msgWrap2 := newMsgWrapT(msg2, sig2, sn2Scratch)
	msgWrap2B := encodeMsgWrapT(msgWrap2)
	ret2Empt := make([]byte, 0)
	rpcCall(RPCPUT, msgWrap2B, ret2Empt)

	return msgWrap1.sn, ERRNONE
}

// Returns true if protocol error'd out or passed.
// Returns false if adversary defeated main protocol goal.
func game() bool {
	skAlice, vkAlice := makeKeys()
	skBob, vkBob := makeKeys()
    aliceSn := new(uint64)
    aliceErr := new(bool)
    bobSn := new(uint64)
    bobErr := new(bool)

	wg := new(sync.WaitGroup)
	wg.Add(2)
	go func() {
        *aliceSn, *aliceErr = aliceMain(skAlice, vkBob)
		wg.Done()
	}()
	go func() {
		*bobSn, *bobErr = bobMain(skBob, vkAlice)
		wg.Done()
	}()
	wg.Wait()


    if !*aliceErr && !*bobErr && *aliceSn != *bobSn {
        return false
    }
    return true
}
