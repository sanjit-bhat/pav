package shared

type ErrorT = uint64

const (
	// Errors
	ErrNone ErrorT = 0
	ErrSome ErrorT = 1
    ErrKeyCliAuditPrefix ErrorT = 2
    ErrKeyCliLookupPrefix ErrorT = 3
    ErrKeyCliNoKey ErrorT = 4
    ErrKeyCliRegPrefix ErrorT = 5
    ErrAudDoPrefix ErrorT = 6
    ErrKeyCliRegNoExist ErrorT = 7
	// Sig
	SigLen uint64 = 69
)
