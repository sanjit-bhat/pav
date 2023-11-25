package full

import (
	"sync"
)

type errorT = bool

const (
	ERRNONE bool = false
	ERRSOME bool = true
)

type msgT struct {
	body uint64
}

type ChatCli struct {
	log  []*msgT
	lock *sync.Mutex
}

func Init() *ChatCli {
	c := &ChatCli{}
	c.log = make([]*msgT, 0)
	c.lock = new(sync.Mutex)
	return c
}

func (c *ChatCli) Put(m *msgT) {
	c.lock.Lock()
	c.log = append(c.log, m)
	c.lock.Unlock()
}

func (c *ChatCli) Get() []*msgT {
	c.lock.Lock()
	ret := make([]*msgT, len(c.log))
	copy(ret, c.log)
	c.lock.Unlock()
	return ret
}
