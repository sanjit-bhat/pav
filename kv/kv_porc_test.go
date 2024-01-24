package kv

import (
	"encoding/json"
	"fmt"
	porc "github.com/anishathalye/porcupine"
	"log"
	"os"
	"slices"
	"testing"
)

// Code based off of:
// https://github.com/anishathalye/porcupine/blob/master/porcupine_test.go

func TestPorc(t *testing.T) {
	ops := parseAllLogs()
	model := kvModel
	porc.CheckOperations(model, ops)
}

type kvInput struct {
	op    uint64
	key   uint64
	value string
}

type kvOutput struct {
	value string
}

var kvModel = porc.Model{
	Partition: func(history []porc.Operation) [][]porc.Operation {
		m := make(map[uint64][]porc.Operation)
		for _, v := range history {
			key := v.Input.(kvInput).key
			m[key] = append(m[key], v)
		}
		keys := make([]uint64, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		ret := make([][]porc.Operation, 0, len(keys))
		for _, k := range keys {
			ret = append(ret, m[k])
		}
		return ret
	},
	Init: func() interface{} {
		// note: we are modeling a single key's value here;
		// we're partitioning by key, so this is okay
		return ""
	},
	Step: func(state, input, output interface{}) (bool, interface{}) {
		inp := input.(kvInput)
		out := output.(kvOutput)
		st := state.(string)
		switch inp.op {
		case opGet:
			return out.value == st, state
		case opPut:
			return true, inp.value
		default:
			return false, inp.value
		}
	},
	DescribeOperation: func(input, output interface{}) string {
		inp := input.(kvInput)
		out := output.(kvOutput)
		switch inp.op {
		case opGet:
			return fmt.Sprintf("get('%v') -> '%v'", inp.key, out.value)
		case opPut:
			return fmt.Sprintf("put('%v', '%v')", inp.key, inp.value)
		default:
			return "<invalid>"
		}
	},
}

type loggedOp struct {
	Msg, Value      string
	Key, Start, End uint64
}

func parseAllLogs() []porc.Operation {
	numClients := 10
	ops := make([]porc.Operation, 0)
	for i := 0; i < numClients; i++ {
		ops = append(ops, parseOneLog(i)...)
	}
	return ops
}

func parseOneLog(cid int) []porc.Operation {
	f, err := os.Open(fmt.Sprintf("logs/cli%d.log", cid))
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	ops := make([]porc.Operation, 0)
	dec := json.NewDecoder(f)
	for dec.More() {
		var lo loggedOp
		if err := dec.Decode(&lo); err != nil {
			log.Fatal(err)
		}
		ops = append(ops, convLoggedOp(cid, &lo))
	}

	return ops
}

func convLoggedOp(cid int, lo *loggedOp) porc.Operation {
	opcode := convMsg(lo.Msg)
	in := kvInput{op: opcode, key: lo.Key}
	out := kvOutput{}
	switch opcode {
	case opGet:
		out.value = lo.Value
	case opPut:
		in.value = lo.Value
	}
	op := porc.Operation{ClientId: cid, Input: in, Call: int64(lo.Start), Output: out, Return: int64(lo.End)}
	return op
}

func convMsg(msg string) uint64 {
	switch msg {
	case "get":
		return opGet
	case "put":
		return opPut
	default:
		log.Fatal("invalid op")
		return 0
	}
}
