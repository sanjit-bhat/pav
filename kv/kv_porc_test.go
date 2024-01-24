package kv

// Code based on:
// https://github.com/anishathalye/porcupine/blob/master/porcupine_test.go

import (
	"encoding/json"
	"fmt"
	porc "github.com/anishathalye/porcupine"
	"log"
	"os"
	"slices"
	"testing"
	"time"
)

func TestPorc(t *testing.T) {
    // Note: run kv_test.go:TestManyOps first to generate traces.
	ops := parseAllLogs(t)
	model := kvModel
	res, info := porc.CheckOperationsVerbose(model, ops, time.Second)
	if res != porc.Ok {
		t.Fatal("supposed to be linearizable")
	}

	file, err := os.CreateTemp("", "*.html")
	if err != nil {
		t.Fatal("failed to create temp file")
	}
	err = porc.Visualize(model, info, file)
	if err != nil {
		t.Fatalf("visualization failed")
	}
	t.Logf("wrote visualization to %s", file.Name())
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

func parseAllLogs(t *testing.T) []porc.Operation {
	numClients := 10
	ops := make([]porc.Operation, 0)
	for i := 0; i < numClients; i++ {
		ops = append(ops, parseOneLog(t, i)...)
	}
	return ops
}

func parseOneLog(t *testing.T, cid int) []porc.Operation {
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
		ops = append(ops, convLoggedOp(t, cid, &lo))
	}

	return ops
}

func convLoggedOp(t *testing.T, cid int, lo *loggedOp) porc.Operation {
	opcode := convMsg(t, lo.Msg)
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

func convMsg(t *testing.T, msg string) uint64 {
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
