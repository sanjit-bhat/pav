// Package benchutil reports benchmark results.
// it heavily borrows code from the stdlib "testing" pkg.
package benchutil

import (
	"fmt"
	"io"
	"math"
	"runtime"
	"strings"
)

type Metric struct {
	N    float64
	Unit string
}

func Report(nOps int, ms []*Metric) {
	buf := new(strings.Builder)
	fmt.Fprintf(buf, "%-*s", 20, callerName(1))
	fmt.Fprintf(buf, "\t%8d", nOps)
	for _, m := range ms {
		buf.WriteByte('\t')
		prettyPrint(buf, m.N, m.Unit)
	}
	fmt.Println(buf.String())
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
