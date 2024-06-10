package ktmerkle

import (
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/pav/cryptoffi"
	"github.com/mit-pdos/pav/merkle"
	"github.com/tchajed/goose/machine"
)

const (
	rpcKeyServUpdateEpoch  uint64 = 1
	rpcKeyServPut          uint64 = 2
	rpcKeyServGetIdAtEpoch uint64 = 3
	rpcKeyServGetIdLatest  uint64 = 4
	rpcKeyServGetDigest    uint64 = 5
	rpcAuditorUpdate       uint64 = 1
	rpcAuditorGetLink      uint64 = 2
)

func callPut(cli *urpc.Client, id merkle.Id, val merkle.Val) (epochTy, cryptoffi.Sig, errorTy) {
	argB := (&putArg{id: id, val: val}).encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(rpcKeyServPut, argB, &replyB, 100)
	machine.Assume(err0 == urpc.ErrNone)
	reply := &putReply{}
	_, err1 := reply.decode(replyB)
	if err1 {
		return 0, nil, err1
	}
	return reply.epoch, reply.sig, reply.error
}

func callGetIdAtEpoch(cli *urpc.Client, id merkle.Id, epoch epochTy) *getIdAtEpochReply {
	errReply := &getIdAtEpochReply{}
	errReply.error = errSome
	argB := (&getIdAtEpochArg{id: id, epoch: epoch}).encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(rpcKeyServGetIdAtEpoch, argB, &replyB, 100)
	machine.Assume(err0 == urpc.ErrNone)
	reply := &getIdAtEpochReply{}
	_, err1 := reply.decode(replyB)
	if err1 {
		return errReply
	}
	return reply
}

func callGetIdLatest(cli *urpc.Client, id merkle.Id) *getIdLatestReply {
	errReply := &getIdLatestReply{}
	errReply.error = errSome
	argB := (&getIdLatestArg{id: id}).encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(rpcKeyServGetIdLatest, argB, &replyB, 100)
	machine.Assume(err0 == urpc.ErrNone)
	reply := &getIdLatestReply{}
	_, err1 := reply.decode(replyB)
	if err1 {
		return errReply
	}
	return reply
}

func callGetDigest(cli *urpc.Client, epoch epochTy) (merkle.Digest, cryptoffi.Sig, errorTy) {
	argB := (&getDigestArg{epoch: epoch}).encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(rpcKeyServGetDigest, argB, &replyB, 100)
	machine.Assume(err0 == urpc.ErrNone)
	reply := &getDigestReply{}
	_, err1 := reply.decode(replyB)
	if err1 {
		return nil, nil, err1
	}
	return reply.digest, reply.sig, reply.error
}

func callUpdate(cli *urpc.Client, epoch epochTy, dig merkle.Digest, sig cryptoffi.Sig) errorTy {
	argB := (&updateArg{epoch: epoch, digest: dig, sig: sig}).encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(rpcAuditorUpdate, argB, &replyB, 100)
	machine.Assume(err0 == urpc.ErrNone)
	reply := &updateReply{}
	_, err1 := reply.decode(replyB)
	if err1 {
		return err1
	}
	return reply.error
}

func callGetLink(cli *urpc.Client, epoch epochTy) (linkTy, cryptoffi.Sig, errorTy) {
	argB := (&getLinkArg{epoch: epoch}).encode()
	replyB := make([]byte, 0)
	err0 := cli.Call(rpcAuditorGetLink, argB, &replyB, 100)
	machine.Assume(err0 == urpc.ErrNone)
	reply := &getLinkReply{}
	_, err1 := reply.decode(replyB)
	if err1 {
		return nil, nil, err1
	}
	return reply.link, reply.sig, reply.error
}

func (s *keyServ) start(addr grove_ffi.Address) {
	handlers := make(map[uint64]func([]byte, *[]byte))

	handlers[rpcKeyServUpdateEpoch] =
		func(enc_args []byte, enc_reply *[]byte) {
			s.updateEpoch()
		}

	handlers[rpcKeyServPut] =
		func(enc_args []byte, enc_reply *[]byte) {
			args := &putArg{}
			_, err0 := args.decode(enc_args)
			if err0 {
				*enc_reply = (&putReply{epoch: 0, error: err0}).encode()
				return
			}
			epoch, sig, err1 := s.put(args.id, args.val)
			*enc_reply = (&putReply{epoch: epoch, sig: sig, error: err1}).encode()
		}

	handlers[rpcKeyServGetIdAtEpoch] =
		func(enc_args []byte, enc_reply *[]byte) {
			args := &getIdAtEpochArg{}
			_, err0 := args.decode(enc_args)
			if err0 {
				reply := &getIdAtEpochReply{}
				reply.error = errSome
				*enc_reply = reply.encode()
				return
			}
			reply := s.getIdAtEpoch(args.id, args.epoch)
			*enc_reply = reply.encode()
		}

	handlers[rpcKeyServGetIdLatest] =
		func(enc_args []byte, enc_reply *[]byte) {
			args := &getIdLatestArg{}
			_, err0 := args.decode(enc_args)
			if err0 {
				reply := &getIdLatestReply{}
				reply.error = errSome
				*enc_reply = reply.encode()
				return
			}
			reply := s.getIdLatest(args.id)
			*enc_reply = reply.encode()
		}

	handlers[rpcKeyServGetDigest] =
		func(enc_args []byte, enc_reply *[]byte) {
			args := &getDigestArg{}
			_, err0 := args.decode(enc_args)
			if err0 {
				reply := &getDigestReply{}
				reply.error = errSome
				*enc_reply = reply.encode()
				return
			}
			dig, sig, err1 := s.getDigest(args.epoch)
			*enc_reply = (&getDigestReply{digest: dig, sig: sig, error: err1}).encode()
		}

	urpc.MakeServer(handlers).Serve(addr)
}

func (a *auditor) start(addr grove_ffi.Address) {
	handlers := make(map[uint64]func([]byte, *[]byte))

	handlers[rpcAuditorUpdate] =
		func(enc_args []byte, enc_reply *[]byte) {
			args := &updateArg{}
			_, err0 := args.decode(enc_args)
			if err0 {
				reply := &updateReply{}
				reply.error = errSome
				*enc_reply = reply.encode()
				return
			}
			err1 := a.update(args.epoch, args.digest, args.sig)
			*enc_reply = (&updateReply{error: err1}).encode()
		}

	handlers[rpcAuditorGetLink] =
		func(enc_args []byte, enc_reply *[]byte) {
			args := &getLinkArg{}
			_, err0 := args.decode(enc_args)
			if err0 {
				reply := &getLinkReply{}
				reply.error = errSome
				*enc_reply = reply.encode()
				return
			}
			link, sig, err1 := a.getLink(args.epoch)
			*enc_reply = (&getLinkReply{link: link, sig: sig, error: err1}).encode()
		}

	urpc.MakeServer(handlers).Serve(addr)
}
