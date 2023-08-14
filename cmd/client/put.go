package main

import (
	"context"	
	"log"
	"time"

	"github.com/mit-pdos/secure-chat/internal/ffi"
	pb "github.com/mit-pdos/secure-chat/internal/proto"
	"google.golang.org/protobuf/proto"
)

func (c *client) getPins() []*pb.Pin {
	c.msgs.mu.Lock()
	defer c.msgs.mu.Unlock()
	msgs := c.msgs.data
	pins := make([]*pb.Pin, 0, len(msgs))
	for seqNum, msgWrap := range msgs {
		pin := &pb.Pin{
			SeqNum: uint64(seqNum), Hash: msgWrap.Hash,
		}
		pins = append(pins, pin)
	}
	return pins
}

func (c *client) hashSign(msg *pb.Msg) (*pb.MsgWrap, error) {
	mb, err := proto.Marshal(msg)
	if err != nil {
		return nil, err
	}
	s, err := c.signer.Sign(mb)
	if err != nil {
		return nil, err
	}
	h := ffi.Hash(mb)
	return &pb.MsgWrap{Msg: msg, Hash: h, Sig: s}, nil
}

func (c *client) putMsg(body *string) error {
	m := &pb.Msg{Sender: c.name, Body: *body, Pins: c.getPins()}
	mw, err := c.hashSign(m)
	if err != nil {
		return err
	}

	for {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := c.rpc.PutMsg(ctx, &pb.PutMsgReq{Msg: mw})
		// Need to cancel now, as opposed to deferring, to not leak contexts inside loop.
		cancel()
		if err != nil {
			log.Println("put rpc returned an err, retrying...")
		} else {
			break
		}
	}
	return nil
}
