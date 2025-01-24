package merkle

import (
	"bytes"
	"fmt"
	"github.com/mit-pdos/pav/cryptoffi"
	"io"
	"math"
	"math/rand/v2"
	"runtime"
	"strings"
	"testing"
	"time"
)

var val = []byte("val")

const (
	// TODO: use diff # ops per bench to run for long enough.
	// e.g., Get's are blazing fast. 1M runs in a few ms.
	// for Put's, 1M takes 3s. but make seed big to reduce var across ops.
	// nSeed should be fairly fixed across benchmarks.
	nSeed int = 100
	nOps  int = 1_000_000
)

func TestBenchGet(t *testing.T) {
	tr, _, label := setup(t, nSeed)

	start := time.Now()
	for i := 0; i < nOps; i++ {
		// TODO: querying a fixed label isn't realistic. it's in the cache.
		_, _, errb := tr.Get(label)
		if errb {
			t.Fatal()
		}
	}
	elap := time.Since(start)

	m0 := float64(elap.Nanoseconds()) / float64(nOps)
	report(nOps, []*metric{{m0, "ns/op"}})
}

func TestBenchProve(t *testing.T) {
	tr, _, label := setup(t, nSeed)

	start := time.Now()
	for i := 0; i < nOps; i++ {
		_, _, _, _, errb := tr.Prove(label)
		if errb {
			t.Fatal()
		}
	}
	elap := time.Since(start)

	m0 := float64(elap.Nanoseconds()) / float64(nOps)
	report(nOps, []*metric{{m0, "ns/op"}})
}

func TestBenchPut(t *testing.T) {
	tr, rnd, label := setup(t, nSeed)

	var total time.Duration
	for i := 0; i < nOps; i++ {
		_, err := rnd.Read(label)
		if err != nil {
			t.Fatal(err)
		}
		l0 := bytes.Clone(label)
		v0 := bytes.Clone(val)

		// TODO: hopefully Put time much more than time.Now overhead.
		// alt, rnd bytes and cloning is only 20ns ish.
		start := time.Now()
		errb := tr.Put(l0, v0)
		if errb {
			t.Fatal()
		}
		total += time.Since(start)
	}

	m0 := float64(total.Nanoseconds()) / float64(nOps)
	report(nOps, []*metric{{m0, "ns/op"}})
}

func setup(t *testing.T, sz int) (tr *Tree, rnd *rand.ChaCha8, label []byte) {
	// TODO: not sure if this helps much.
	// runtime.GC()
	tr = NewTree()
	var seed [32]byte
	rnd = rand.NewChaCha8(seed)
	label = make([]byte, cryptoffi.HashLen)

	for i := 0; i < sz; i++ {
		_, err := rnd.Read(label)
		if err != nil {
			t.Fatal(err)
		}
		l := bytes.Clone(label)
		v := bytes.Clone(val)
		errb := tr.Put(l, v)
		if errb {
			t.Fatal()
		}
	}
	return
}

type metric struct {
	n    float64
	unit string
}

// callerName gives the function name for the caller,
// after skip frames (where 0 means the current function).
func callerName(skip int) string {
	pcs := make([]uintptr, 1)
	callers := runtime.Callers(skip+2, pcs) // skip + runtime.Callers + callerName
	if callers == 0 {
		panic("bench: zero callers found")
	}
	frames := runtime.CallersFrames(pcs)
	frame, _ := frames.Next()
	fullName := frame.Function
	split := strings.Split(fullName, ".")
	fnName := split[len(split)-1]
	return fnName
}

func prettyPrint(w io.Writer, x float64, unit string) {
	// Print all numbers with 10 places before the decimal point
	// and small numbers with four sig figs. Field widths are
	// chosen to fit the whole part in 10 places while aligning
	// the decimal point of all fractional formats.
	var format string
	switch y := math.Abs(x); {
	case y == 0 || y >= 999.95:
		format = "%10.0f %s"
	case y >= 99.995:
		format = "%12.1f %s"
	case y >= 9.9995:
		format = "%13.2f %s"
	case y >= 0.99995:
		format = "%14.3f %s"
	case y >= 0.099995:
		format = "%15.4f %s"
	case y >= 0.0099995:
		format = "%16.5f %s"
	case y >= 0.00099995:
		format = "%17.6f %s"
	default:
		format = "%18.7f %s"
	}
	fmt.Fprintf(w, format, x, unit)
}

func report(nOps int, ms []*metric) {
	buf := new(strings.Builder)
	fmt.Fprintf(buf, "%s", callerName(1))
	fmt.Fprintf(buf, "\t%8d", nOps)
	for _, m := range ms {
		buf.WriteByte('\t')
		prettyPrint(buf, m.n, m.unit)
	}
	fmt.Println(buf.String())
}
