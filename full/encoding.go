package full

type errorT = bool

const (
	ERRNONE bool = false
	ERRSOME bool = true
)

type msgT struct {
	body uint64
}
