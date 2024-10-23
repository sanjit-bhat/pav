package kt

type HistEntry struct {
	Epoch   uint64
	HistVal []byte
}

// GetHist searches hist at the epoch and rets the latest val, or false
// if there's no registered val.
func GetHist(o []*HistEntry, epoch uint64) (bool, []byte) {
	var isReg bool
	var val []byte
	// entries inv: ordered by epoch field.
	for _, e := range o {
		if e.Epoch <= epoch {
			isReg = true
			val = e.HistVal
		}
	}
	return isReg, val
}
