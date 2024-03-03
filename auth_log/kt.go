package auth_log

import (
	"github.com/mit-pdos/secure-chat/auth_log/shared"
)

// KeyServ just instantiates an AuthLog and re-exports all its methods.
type KeyServ struct {
}

type Auditor struct {
}

func NewAuditor() *Auditor {
	panic("todo")
}

func (a *Auditor) Update() {
	panic("todo")
}

/*
User can query auditor and ask it to present some of its last roots.
User can then check that either is a prefix of the other.
One problem is that the user only has some latest root,
and some other (not neces contiguous) root.
It can check to see if those roots are contained in the auditor's roots.
And that way know prefix up to that epoch.
But due to the client gaps, might not get as much overlap as possible.

Impl-wise, let's do this without urpc at first.
When our data structures are already changing,
we don't want to have to re-implement crap.
At some point, we might want to write a simple program
that takes a struct and auto-gen's the serialization.
*/

func (a *Auditor) Get() []*Digest {
	panic("todo")
}

type KeyCli struct {
}

func (c *KeyCli) Register(e *Entry) (uint64, shared.ErrorT) {
	panic("todo")
}

func (c *KeyCli) Lookup(uname uint64) (uint64, []byte, shared.ErrorT) {
	panic("todo")
}

func (c *KeyCli) Audit(adtrId uint64) (uint64, shared.ErrorT) {
	panic("todo")
}
