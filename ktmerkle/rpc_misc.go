package ktmerkle

// This file has code that probably should be auto-generated,
// but I haven't gotten around to that yet.

import (
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/merkle"
	"github.com/tchajed/goose/machine"
)

const (
	rpcServUpdateEpoch uint64 = 1
	rpcServPut         uint64 = 2
	rpcServGetIdAt     uint64 = 3
	// rpcServGetIdNow    uint64 = 4
	rpcServGetDig  uint64 = 5
	rpcServGetLink uint64 = 6
	rpcAdtrPut     uint64 = 7
	rpcAdtrGet     uint64 = 8
)

func callServUpdateEpoch(cli *urpc.Client) {
	argB := make([]byte, 0)
	replyB := make([]byte, 0)
	err0 := cli.Call(rpcServUpdateEpoch, argB, &replyB, 100)
	machine.Assume(err0 == urpc.ErrNone)
}

func callServPut(cli *urpc.Client, id merkle.Id, val merkle.Val) *servPutReply {
	argB := (&servPutArg{id: id, val: val}).encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(rpcServPut, argB, &replyB, 100)
	machine.Assume(err0 == urpc.ErrNone)
	reply := &servPutReply{}
	_, err1 := reply.decode(replyB)
	if err1 {
		errReply := &servPutReply{}
		errReply.error = err1
		return errReply
	}
	return reply
}

func callServGetIdAt(cli *urpc.Client, id merkle.Id, epoch epochTy) *servGetIdAtReply {
	argB := (&servGetIdAtArg{id: id, epoch: epoch}).encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(rpcServGetIdAt, argB, &replyB, 100)
	machine.Assume(err0 == urpc.ErrNone)
	reply := &servGetIdAtReply{}
	_, err1 := reply.decode(replyB)
	if err1 {
		errReply := &servGetIdAtReply{}
		errReply.error = err1
		return errReply
	}
	return reply
}

/*
func callServGetIdNow(cli *urpc.Client, id merkle.Id) *servGetIdNowReply {
	argB := (&servGetIdNowArg{id: id}).encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(rpcServGetIdNow, argB, &replyB, 100)
	machine.Assume(err0 == urpc.ErrNone)
	reply := &servGetIdNowReply{}
	_, err1 := reply.decode(replyB)
	if err1 {
		errReply := &servGetIdNowReply{}
		errReply.error = err1
		return errReply
	}
	return reply
}
*/

func callServGetLink(cli *urpc.Client, epoch epochTy) *servGetLinkReply {
	argB := (&servGetLinkArg{epoch: epoch}).encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(rpcServGetLink, argB, &replyB, 100)
	machine.Assume(err0 == urpc.ErrNone)
	reply := &servGetLinkReply{}
	_, err1 := reply.decode(replyB)
	if err1 {
		errReply := &servGetLinkReply{}
		errReply.error = err1
		return errReply
	}
	return reply
}

func (s *server) start(addr grove_ffi.Address) {
	handlers := make(map[uint64]func([]byte, *[]byte))

	handlers[rpcServUpdateEpoch] =
		func(enc_args []byte, enc_reply *[]byte) {
			s.updateEpoch()
		}

	handlers[rpcServPut] =
		func(enc_args []byte, enc_reply *[]byte) {
			args := &servPutArg{}
			_, err0 := args.decode(enc_args)
			if err0 {
				reply := &servPutReply{}
				reply.error = err0
				*enc_reply = reply.encode()
				return
			}
			*enc_reply = s.put(args.id, args.val).encode()
		}

	handlers[rpcServGetIdAt] =
		func(enc_args []byte, enc_reply *[]byte) {
			args := &servGetIdAtArg{}
			_, err0 := args.decode(enc_args)
			if err0 {
				reply := &servGetIdAtReply{}
				reply.error = errSome
				*enc_reply = reply.encode()
				return
			}
			*enc_reply = s.getIdAt(args.id, args.epoch).encode()
		}

		/*
			handlers[rpcServGetIdNow] =
				func(enc_args []byte, enc_reply *[]byte) {
					args := &servGetIdNowArg{}
					_, err0 := args.decode(enc_args)
					if err0 {
						reply := &servGetIdNowReply{}
						reply.error = errSome
						*enc_reply = reply.encode()
						return
					}
					*enc_reply = s.getIdNow(args.id).encode()
				}
		*/

	handlers[rpcServGetLink] =
		func(enc_args []byte, enc_reply *[]byte) {
			args := &servGetLinkArg{}
			_, err0 := args.decode(enc_args)
			if err0 {
				reply := &servGetLinkReply{}
				reply.error = errSome
				*enc_reply = reply.encode()
				return
			}
			*enc_reply = s.getLink(args.epoch).encode()
		}

	urpc.MakeServer(handlers).Serve(addr)
}

func callAdtrPut(cli *urpc.Client, prevLink linkTy, dig merkle.Digest, servSig cryptoffi.Sig) errorTy {
	argB := (&adtrPutArg{prevLink: prevLink, dig: dig, servSig: servSig}).encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(rpcAdtrPut, argB, &replyB, 100)
	machine.Assume(err0 == urpc.ErrNone)
	reply := &adtrPutReply{}
	_, err1 := reply.decode(replyB)
	if err1 {
		return err1
	}
	return reply.error
}

func callAdtrGet(cli *urpc.Client, epoch epochTy) *adtrGetReply {
	argB := (&adtrGetArg{epoch: epoch}).encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(rpcAdtrGet, argB, &replyB, 100)
	machine.Assume(err0 == urpc.ErrNone)
	reply := &adtrGetReply{}
	_, err1 := reply.decode(replyB)
	if err1 {
		errReply := &adtrGetReply{}
		errReply.error = err1
		return errReply
	}
	return reply
}

func (a *auditor) start(addr grove_ffi.Address) {
	handlers := make(map[uint64]func([]byte, *[]byte))

	handlers[rpcAdtrPut] =
		func(enc_args []byte, enc_reply *[]byte) {
			args := &adtrPutArg{}
			_, err0 := args.decode(enc_args)
			if err0 {
				reply := &adtrPutReply{}
				reply.error = errSome
				*enc_reply = reply.encode()
				return
			}
			err1 := a.put(args.prevLink, args.dig, args.servSig)
			*enc_reply = (&adtrPutReply{error: err1}).encode()
		}

	handlers[rpcAdtrGet] =
		func(enc_args []byte, enc_reply *[]byte) {
			args := &adtrGetArg{}
			_, err0 := args.decode(enc_args)
			if err0 {
				reply := &adtrGetReply{}
				reply.error = errSome
				*enc_reply = reply.encode()
				return
			}
			*enc_reply = a.get(args.epoch).encode()
		}

	urpc.MakeServer(handlers).Serve(addr)
}
