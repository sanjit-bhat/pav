package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"

	"github.com/mit-pdos/secure-chat/internal/ffi"
	pb "github.com/mit-pdos/secure-chat/internal/proto"
	"google.golang.org/protobuf/proto"
)

func (c *client) setCancel(f context.CancelCauseFunc) error {
	c.cancel.mu.Lock()
	defer c.cancel.mu.Unlock()
	if c.cancel.done {
		return errors.New("client already ended connection")
	} else {
		c.cancel.data = f
		return nil
	}
}

func checkHash(msgWrap *pb.MsgWrap) error {
	mb, err := proto.Marshal(msgWrap.Msg)
	if err != nil {
		return err
	}
	ref := ffi.Hash(mb)
	if !bytes.Equal(ref, msgWrap.Hash) {
		return errors.New("given hash does not match reference hash")
	}
	return nil
}

func (c *client) checkSig(msgWrap *pb.MsgWrap) error {
	v, ok := c.verifiers[unameT(msgWrap.Msg.Sender)]
	if !ok {
		return errors.New("do not have public key for user")
	}
	mb, err := proto.Marshal(msgWrap.Msg)
	if err != nil {
		return err
	}
	if err := v.Verify(mb, msgWrap.Sig); err != nil {
		return err
	}
	return nil
}

func (c *client) checkPins(msgWrap *pb.MsgWrap) error {
	c.msgs.mu.Lock()
	defer c.msgs.mu.Unlock()
	msgs := c.msgs.data
	for _, pin := range msgWrap.Msg.Pins {
		pm, ok := msgs[seqNumT(pin.SeqNum)]
		if !ok {
			return errors.New("pinned msg not contained in local history")
		}
		if msgWrap.SeqNum <= pm.SeqNum {
			return errors.New("pinned msg has greater seqNum than actual msg")
		}
		if !bytes.Equal(pm.Hash, pin.Hash) {
			return errors.New("pin has diff msg hash than local history")
		}
	}
	return nil
}

func (c *client) checkSNAdd(msgWrap *pb.MsgWrap) error {
	c.msgs.mu.Lock()
	defer c.msgs.mu.Unlock()
	msgs := c.msgs.data
	if _, ok := msgs[seqNumT(msgWrap.SeqNum)]; ok {
		return errors.New("seqNum already exists in local history")
	}
	msgs[seqNumT(msgWrap.SeqNum)] = msgWrap
	return nil
}

func (c *client) getChecks(msgWrap *pb.MsgWrap) error {
	if err := checkHash(msgWrap); err != nil {
		return err
	}
	if err := c.checkSig(msgWrap); err != nil {
		return err
	}
	if err := c.checkPins(msgWrap); err != nil {
		return err
	}
	if err := c.checkSNAdd(msgWrap); err != nil {
		return err
	}
	return nil
}

func (c *client) getMsgs() {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	if err := c.setCancel(cancel); err != nil {
		return
	}
	stream, err := c.rpc.GetMsgs(ctx, &pb.GetMsgsReq{Sender: c.name})
	if err != nil {
		log.Fatalln("failed getMsgs:", err)
	}

	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			log.Println("server closed getMsgs stream")
			return
		}
		if err != nil {
			if errors.Is(context.Cause(ctx), errUserEndClient) {
				return
			} else {
				log.Fatalln("failed getMsgs stream recv:", err)
			}
		}
		if err = c.getChecks(resp.Msg); err != nil {
			log.Println("failed to add msg:", err)
		}
	}
}
