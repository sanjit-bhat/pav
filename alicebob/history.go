package alicebob

import (
	"github.com/goose-lang/std"
)

type histEntry struct {
	isReg bool
	pk    []byte
}

// extendHist to length numEpochs.
// numEpochs must not be smaller than length hist.
func extendHist(hist []*histEntry, numEpochs uint64) []*histEntry {
	histLen := uint64(len(hist))
	std.Assert(histLen <= numEpochs)
	var last *histEntry
	if histLen == 0 {
		last = &histEntry{}
	} else {
		last = hist[histLen-1]
	}

	var newHist = hist
	var i = histLen
	for ; i < numEpochs; i++ {
		newHist = append(newHist, last)
	}
	return newHist
}
