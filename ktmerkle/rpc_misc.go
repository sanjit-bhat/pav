package ktmerkle

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
	rpcServGetIdNow    uint64 = 4
	rpcServGetDig      uint64 = 5
	rpcServGetLink     uint64 = 6
	rpcAdtrPut         uint64 = 7
	rpcAdtrGet         uint64 = 8
)

func callServPut(cli *urpc.Client, id merkle.Id, val merkle.Val) (epochTy, cryptoffi.Sig, errorTy) {
	argB := (&servPutArg{id: id, val: val}).encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(rpcServPut, argB, &replyB, 100)
	machine.Assume(err0 == urpc.ErrNone)
	reply := &servPutReply{}
	_, err1 := reply.decode(replyB)
	if err1 {
		return 0, nil, err1
	}
	return reply.epoch, reply.sig, reply.error
}

func callServGetIdAt(cli *urpc.Client, id merkle.Id, epoch epochTy) *servGetIdAtReply {
	argB := (&servGetIdAtArg{id: id, epoch: epoch}).encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(rpcServGetIdAt, argB, &replyB, 100)
	machine.Assume(err0 == urpc.ErrNone)
	reply := &servGetIdAtReply{}
	_, err1 := reply.decode(replyB)
	if err1 {
		return &servGetIdAtReply{error: errSome}
	}
	return reply
}

func callServGetIdNow(cli *urpc.Client, id merkle.Id) *servGetIdNowReply {
	argB := (&servGetIdNowArg{id: id}).encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(rpcServGetIdNow, argB, &replyB, 100)
	machine.Assume(err0 == urpc.ErrNone)
	reply := &servGetIdNowReply{}
	_, err1 := reply.decode(replyB)
	if err1 {
		return &servGetIdNowReply{error: errSome}
	}
	return reply
}

func callServGetDig(cli *urpc.Client, epoch epochTy) (merkle.Digest, cryptoffi.Sig, errorTy) {
	argB := (&servGetDigArg{epoch: epoch}).encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(rpcServGetDig, argB, &replyB, 100)
	machine.Assume(err0 == urpc.ErrNone)
	reply := &servGetDigReply{}
	_, err1 := reply.decode(replyB)
	if err1 {
		return nil, nil, err1
	}
	return reply.digest, reply.sig, reply.error
}

func callServGetLink(cli *urpc.Client, epoch epochTy) (linkTy, cryptoffi.Sig, errorTy) {
	argB := (&servGetLinkArg{epoch: epoch}).encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(rpcServGetLink, argB, &replyB, 100)
	machine.Assume(err0 == urpc.ErrNone)
	reply := &servGetLinkReply{}
	_, err1 := reply.decode(replyB)
	if err1 {
		return nil, nil, err1
	}
	return reply.link, reply.sig, reply.error
}

func callAdtrPut(cli *urpc.Client, link linkTy, sig cryptoffi.Sig) errorTy {
	argB := (&adtrPutArg{link: link, sig: sig}).encode()
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

func callAdtrGet(cli *urpc.Client, epoch epochTy) (linkTy, cryptoffi.Sig, cryptoffi.Sig, errorTy) {
	argB := (&adtrGetArg{epoch: epoch}).encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(rpcAdtrGet, argB, &replyB, 100)
	machine.Assume(err0 == urpc.ErrNone)
	reply := &adtrGetReply{}
	_, err1 := reply.decode(replyB)
	if err1 {
		return nil, nil, nil, err1
	}
	return reply.link, reply.servSig, reply.adtrSig, reply.error
}

func (s *serv) start(addr grove_ffi.Address) {
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
			epoch, sig, err1 := s.put(args.id, args.val)
			*enc_reply = (&servPutReply{epoch: epoch, sig: sig, error: err1}).encode()
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
			reply := s.getIdAt(args.id, args.epoch)
			*enc_reply = reply.encode()
		}

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
			reply := s.getIdNow(args.id)
			*enc_reply = reply.encode()
		}

	handlers[rpcServGetDig] =
		func(enc_args []byte, enc_reply *[]byte) {
			args := &servGetDigArg{}
			_, err0 := args.decode(enc_args)
			if err0 {
				reply := &servGetDigReply{}
				reply.error = errSome
				*enc_reply = reply.encode()
				return
			}
			dig, sig, err1 := s.getDig(args.epoch)
			*enc_reply = (&servGetDigReply{digest: dig, sig: sig, error: err1}).encode()
		}

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
			link, sig, err1 := s.getLink(args.epoch)
			*enc_reply = (&servGetLinkReply{link: link, sig: sig, error: err1}).encode()
		}

	urpc.MakeServer(handlers).Serve(addr)
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
			err1 := a.put(args.link, args.sig)
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
			link, servSig, adtrSig, err1 := a.get(args.epoch)
			*enc_reply = (&adtrGetReply{link: link, servSig: servSig, adtrSig: adtrSig, error: err1}).encode()
		}

	urpc.MakeServer(handlers).Serve(addr)
}
