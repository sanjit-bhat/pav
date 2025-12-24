package ktcore

// Blame a specific party when a bad thing happens.
// if a party is good, we should not see its [Blame] code.
type Blame uint64

const BlameNone Blame = 0

const (
	// BlameServSig faults a signing predicate,
	// whereas [BlameServFull] faults the full server RPC protocol,
	// which is generally a superset of trust assumptions.
	// KT irrefutable evidence (i.e., whistleblowing) only relies on [BlameServSig].
	BlameServSig Blame = 1 << iota
	BlameServFull
	BlameAdtrSig
	BlameAdtrFull
	BlameClients
	// BlameUnknown should only be used sparingly.
	// it's the equivalent of throwing up your hands in despair.
	// in this system, these are the only [BlameUnknown]s:
	//  * misc network errors.
	//  * Auditor.Get errors.
	BlameUnknown
)
