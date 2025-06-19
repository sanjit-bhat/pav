package auditor

type UpdateReply struct {
	Err bool
}

type GetArg struct {
	Epoch uint64
}

type GetReply struct {
	Link        []byte
	ServLinkSig []byte
	AdtrLinkSig []byte
	VrfPk       []byte
	ServVrfSig  []byte
	AdtrVrfSig  []byte
	Err         bool
}
