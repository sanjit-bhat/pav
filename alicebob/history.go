package alicebob

type histEntry struct {
	isReg bool
	pk    []byte
}

// extendHist to length numEpochs.
// error if numEpochs smaller than length hist.
func extendHist(hist []*histEntry, numEpochs uint64) (bool, []*histEntry) {
	histLen := uint64(len(hist))
	if numEpochs < histLen {
		return true, hist
	}

	var last *histEntry
	if histLen == 0 {
		last = &histEntry{}
	} else {
		last = hist[histLen-1]
	}

	var newHist = hist
	var i = histLen
	for i < numEpochs {
		newHist = append(newHist, last)
		i++
	}
	return false, newHist
}
