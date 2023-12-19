package fc_ffi

import (
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/secure-chat/full2/shared"
	"sync"
)

type Server struct {
	log  []byte
	lock *sync.Mutex
}

func (s *Server) Put(m []byte) {
	s.lock.Lock()
	s.log = m
	s.lock.Unlock()
}

func (s *Server) Get() []byte {
	s.lock.Lock()
	ret := s.log
	s.lock.Unlock()
	return ret
}

func MakeServer() *Server {
	return &Server{lock: new(sync.Mutex)}
}

func (s *Server) Start(me grove_ffi.Address) {
	handlers := make(map[uint64]func([]byte, *[]byte))

	handlers[shared.RpcPut] =
		func(enc_args []byte, enc_reply *[]byte) {
			s.Put(enc_args)
		}

	handlers[shared.RpcGet] =
		func(enc_args []byte, enc_reply *[]byte) {
			*enc_reply = s.Get()
		}

	urpc.MakeServer(handlers).Serve(me)
}
