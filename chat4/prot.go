package chat4

import "sync"

func aliceMain(skAlice *signerT, vkBob []byte) (uint64, errorT) {
	// Event 1.
	// Makes Alice's first msg, signs it, and sends it over the network.
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
	// Receives Alice's msg, with an sn assigned to it.
	args2Empt := make([]byte, 0)
	msgWrap2B := newMsgWrapTSlice()
	rpcCall(RPCGET, args2Empt, msgWrap2B)
	// Decoding bytes we don't know, apart from the len.
	msgWrap2, _ := decodeMsgWrapT(msgWrap2B)

	// Event 4.
	// Receives Bob's msg, which has a pin to the sn assigned to Alice's first msg.
	args3Empt := make([]byte, 0)
	msgWrap3B := newMsgWrapTSlice()
	rpcCall(RPCGET, args3Empt, msgWrap3B)
	// Decoding bytes we don't know, apart from the len.
	msgWrap3, _ := decodeMsgWrapT(msgWrap3B)
	msg3B := encodeMsgT(msgWrap3.msg)
	err3 := verify(vkBob, msg3B, msgWrap3.sig)
	if err3 {
		return 0, err3
	}

	// Event 5.
	// Compares the sn Alice received to the sn Bob received.
	if msgWrap2.sn != msgWrap3.msg.pin {
		return 0, ERRSOME
	}

	return msgWrap2.sn, ERRNONE
}

func bobMain(skBob *signerT, vkAlice []byte) (uint64, errorT) {
	// Event 2.2.
	// Receives Alice's msg, with an sn assigned to it.
	args1Empt := make([]byte, 0)
	msgWrap1B := newMsgWrapTSlice()
	rpcCall(RPCGET, args1Empt, msgWrap1B)
	// Decoding bytes we don't know, apart from the len.
	msgWrap1, _ := decodeMsgWrapT(msgWrap1B)

	// Event 3.
	// Makes a new msg, with a pin back to the sn for Alice's msg.
	// Signs it and sends it over the network.
	tag2 := uint64(2)
	body2 := uint64(8959)
	// Core protocol: stores Alice's msg sn as pin for Bob's msg.
	msg2 := newMsgT(tag2, body2, msgWrap1.sn)
	msg2B := encodeMsgT(msg2)
	// Encode needs to preserve connection bc of this sign op.
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
	var aliceSn uint64
	var aliceErr bool
	var bobSn uint64
	var bobErr bool

	wg := new(sync.WaitGroup)
    wg.Add(1)
	go func() {
		aliceSn, aliceErr = aliceMain(skAlice, vkBob)
		wg.Done()
	}()
    wg.Add(1)
	go func() {
		bobSn, bobErr = bobMain(skBob, vkAlice)
		wg.Done()
	}()
	wg.Wait()

	return aliceErr || bobErr || aliceSn == bobSn
}
