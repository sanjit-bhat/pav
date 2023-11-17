package full

import (
	"sync"
)

type ChatCli struct {
	log  []msgT
	lock *sync.Mutex
}

func Init() *ChatCli {
	return &ChatCli{log: nil, lock: new(sync.Mutex)}
}

func (c *ChatCli) Put(m msgT) {
	c.lock.Lock()
	c.log = append(c.log, m)
	c.lock.Unlock()
}

func (c *ChatCli) Get() []msgT {
	c.lock.Lock()
	ret := c.log
	c.lock.Unlock()
	return ret
}
