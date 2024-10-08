package kt

type TimeSeriesEntry struct {
	Epoch uint64
	TSVal []byte
}

// GetTimeSeries rets whether a val is registered at the time and, if so, the val.
func GetTimeSeries(o []*TimeSeriesEntry, epoch uint64) (bool, []byte) {
	var isReg bool
	var val []byte
	// entries inv: ordered by epoch field.
	for _, e := range o {
		if e.Epoch <= epoch {
			isReg = true
			val = e.TSVal
		}
	}
	return isReg, val
}
