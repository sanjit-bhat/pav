package main

import (
	"log"

	"github.com/mit-pdos/secure-chat/internal/prompt"
)

func (c *client) nameLoop() {
	for {
		p := prompt.Select{
			Label: "Name",
			Items: getNames(),
		}
		v, err := p.Run()
		if err != nil {
			log.Println("warning: failed prompt:", err)
			continue
		}
		c.name = v
		return
	}
}

func (c *client) msgLoop() {
	for {
		p := prompt.Select{
			Label: "Action",
			Items: []string{"put", "list", "end"},
		}
		v, err := p.Run()
		if err != nil {
			log.Println("warning: failed prompt:", err)
			continue
		}

		if v == "end" {
			c.callCancel()
			return
		} else if v == "list" {
			c.listMsgs()
		} else if v == "put" {
			p := prompt.Prompt{
				Label: "Msg",
			}
			v, err := p.Run()
			if err != nil {
				log.Println("warning: failed prompt:", err)
				continue
			}
			if err = c.putMsg(&v); err != nil {
				log.Println("failed putMsg:", err)
			}
		}
	}
}
