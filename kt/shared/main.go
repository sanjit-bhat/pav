package shared

import (
	"github.com/tchajed/goose/machine"
	"github.com/tchajed/marshal"
)

type ErrorT = uint64

const (
	// Errors
	ErrNone                  ErrorT = 0
	ErrSome                  ErrorT = 1
	ErrKeyCli_AuditPrefix    ErrorT = 2
	ErrKeyCli_CheckLogPrefix ErrorT = 3
	ErrKeyCli_CheckLogLookup ErrorT = 4
	ErrKeyCli_RegNoExist     ErrorT = 5
	ErrUnameKey_Decode       ErrorT = 6
	ErrKeyLog_Decode         ErrorT = 7
	ErrSigLog_Decode         ErrorT = 8
	ErrVerify                ErrorT = 9
	// RPCs
	RpcAppendLog uint64 = 1
	RpcGetLog    uint64 = 2
	RpcDoAudit   uint64 = 3
	RpcGetAudit  uint64 = 4
	// Sig
	SigLen uint64 = 69
)

func BytesEqual(b1 []byte, b2 []byte) bool {
	if len(b1) != len(b2) {
		return false
	}
	var ans = true
	for i, b := range b1 {
		if b != b2[i] {
			ans = false
		}
	}
	return ans
}

type UnameKey struct {
	Uname uint64
	Key   []byte
}

func (uk *UnameKey) DeepCopy() *UnameKey {
	newKey := make([]byte, len(uk.Key))
	copy(newKey, uk.Key)
	return &UnameKey{Uname: uk.Uname, Key: newKey}
}

func (uk1 *UnameKey) IsEqual(uk2 *UnameKey) bool {
	return uk1.Uname == uk2.Uname && BytesEqual(uk1.Key, uk2.Key)
}

func (uk *UnameKey) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, uk.Uname)
	b = marshal.WriteInt(b, uint64(len(uk.Key)))
	b = marshal.WriteBytes(b, uk.Key)
	return b
}

func (uk *UnameKey) Decode(b []byte) ([]byte, ErrorT) {
	if len(b) < 8 {
		return nil, ErrUnameKey_Decode
	}
	uname, b := marshal.ReadInt(b)
	if len(b) < 8 {
		return nil, ErrUnameKey_Decode
	}
	l, b := marshal.ReadInt(b)
	if uint64(len(b)) < l {
		return nil, ErrUnameKey_Decode
	}
	key, b := marshal.ReadBytes(b, l)
	uk.Uname = uname
	uk.Key = key
	return b, ErrNone
}

type KeyLog struct {
	log []*UnameKey
}

func NewKeyLog() *KeyLog {
	return &KeyLog{log: make([]*UnameKey, 0)}
}

func (l *KeyLog) DeepCopy() *KeyLog {
	var newLog = make([]*UnameKey, 0, l.Len())
	for _, entry := range l.log {
		newLog = append(newLog, entry.DeepCopy())
	}
	return &KeyLog{log: newLog}
}

func (small *KeyLog) IsPrefix(big *KeyLog) bool {
	if big.Len() < small.Len() {
		return false
	}
	var ans = true
	for i, log := range small.log {
		if !log.IsEqual(big.log[i]) {
			ans = false
		}
	}
	return ans
}

func (l *KeyLog) Lookup(uname uint64) (uint64, []byte, bool) {
	var idx uint64
	var key []byte
	var ok bool
	for i, entry := range l.log {
		if entry.Uname == uname {
			idx = uint64(i)
			key = entry.Key
			ok = true
		}
	}
	return idx, key, ok
}

func (l *KeyLog) Len() uint64 {
	return uint64(len(l.log))
}

func (l *KeyLog) Append(uk *UnameKey) {
	l.log = append(l.log, uk)
}

func (l *KeyLog) Encode() []byte {
	var b = make([]byte, 0)
	b = marshal.WriteInt(b, l.Len())
	for _, entry := range l.log {
		b = marshal.WriteBytes(b, entry.Encode())
	}
	return b
}

func (l *KeyLog) Decode(b2 []byte) ([]byte, ErrorT) {
	var b = b2
	if len(b) < 8 {
		return nil, ErrKeyLog_Decode
	}
	length, b := marshal.ReadInt(b)
	log := make([]*UnameKey, length)
	var err ErrorT
	for i := uint64(0); i < length; i++ {
		log[i] = new(UnameKey)
		var err2 ErrorT
		b, err2 = log[i].Decode(b)
		if err2 != ErrNone {
			err = err2
		}
	}
	l.log = log
	return b, err
}

type SigLog struct {
	Sig []byte
	Log *KeyLog
}

func NewSigLog(sig []byte, log *KeyLog) *SigLog {
	return &SigLog{Sig: sig, Log: log}
}

func (l *SigLog) Encode() []byte {
	var b = make([]byte, 0)
	machine.Assert(uint64(len(l.Sig)) == SigLen)
	b = marshal.WriteBytes(b, l.Sig)
	b = marshal.WriteBytes(b, l.Log.Encode())
	return b
}

func (l *SigLog) Decode(b []byte) ([]byte, ErrorT) {
	if uint64(len(b)) < SigLen {
		return nil, ErrSigLog_Decode
	}
	sig, b := marshal.ReadBytes(b, SigLen)
	log := new(KeyLog)
	b, err := log.Decode(b)
	if err != ErrNone {
		return nil, err
	}
	l.Sig = sig
	l.Log = log
	return b, ErrNone
}
