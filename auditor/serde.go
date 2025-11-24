package auditor

type GetArg struct {
	Epoch uint64
}

type SignedLink struct {
	Link    []byte
	ServSig []byte
	AdtrSig []byte
}

type SignedVrf struct {
	VrfPk   []byte
	ServSig []byte
	AdtrSig []byte
}

type GetReply struct {
	Link *SignedLink
	Vrf  *SignedVrf
	Err  bool
}
