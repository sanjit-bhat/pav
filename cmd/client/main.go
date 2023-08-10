package main

import (
	"log"
	"sync"
)

func main() {
	c, conn := newClient()
	defer conn.Close()
	c.nameLoop()
	if err := c.loadKeys(); err != nil {
		log.Fatalln("failed to load keys:", err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		c.getMsgs()
	}()
	go func() {
		defer wg.Done()
		c.msgLoop()
	}()
	wg.Wait()
}
