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
	nSeed int = 1_000_000
)

func TestBenchGet(t *testing.T) {
	tr, rnd := setup(t, nSeed)
	label := make([]byte, cryptoffi.HashLen)
	nOps := 1_000_000

	start := time.Now()
	for i := 0; i < nOps; i++ {
		_, err := rnd.Read(label)
		if err != nil {
			t.Fatal(err)
		}
		// this gets non-memb.
		// memb has similar performance, as long as the
		// working set of labels is big enough (1M).
		_, _, errb := tr.Get(label)
		if errb {
			t.Fatal()
		}
	}
	total := time.Since(start)

	m0 := float64(total.Nanoseconds()) / float64(nOps)
	m1 := float64(total.Milliseconds())
	report(nOps, []*metric{{m0, "ns/op"}, {m1, "ms"}})
}

func TestBenchProve(t *testing.T) {
	tr, rnd := setup(t, nSeed)
	label := make([]byte, cryptoffi.HashLen)
	nOps := 1_000_000

	start := time.Now()
	for i := 0; i < nOps; i++ {
		_, err := rnd.Read(label)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, _, errb := tr.Prove(label)
		if errb {
			t.Fatal()
		}
	}
	total := time.Since(start)

	m0 := float64(total.Nanoseconds()) / float64(nOps)
	m1 := float64(total.Milliseconds())
	report(nOps, []*metric{{m0, "ns/op"}, {m1, "ms"}})
}

func TestBenchPut(t *testing.T) {
	tr, rnd := setup(t, nSeed)
	label := make([]byte, cryptoffi.HashLen)
	nOps := 200_000

	start := time.Now()
	for i := 0; i < nOps; i++ {
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
	total := time.Since(start)

	m0 := float64(total.Nanoseconds()) / float64(nOps)
	m1 := float64(total.Milliseconds())
	report(nOps, []*metric{{m0, "ns/op"}, {m1, "ms"}})
}

func setup(t *testing.T, sz int) (tr *Tree, rnd *rand.ChaCha8) {
	tr = NewTree()
	var seed [32]byte
	rnd = rand.NewChaCha8(seed)

	for i := 0; i < sz; i++ {
		label := make([]byte, cryptoffi.HashLen)
		_, err := rnd.Read(label)
		if err != nil {
			t.Fatal(err)
		}
		v := bytes.Clone(val)
		errb := tr.Put(label, v)
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
	fmt.Fprintf(buf, "%-*s", 20, callerName(1))
	fmt.Fprintf(buf, "\t%8d", nOps)
	for _, m := range ms {
		buf.WriteByte('\t')
		prettyPrint(buf, m.n, m.unit)
	}
	fmt.Println(buf.String())
}
