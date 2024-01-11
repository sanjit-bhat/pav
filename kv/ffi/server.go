package ffi

import (
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/gokv/urpc"
	"github.com/mit-pdos/secure-chat/kv/shared"
	"sync"
)

type Server struct {
	log []byte
	mu  *sync.Mutex
}

// Relies on client later calling Commit to unlock.
func (s *Server) Prepare() []byte {
	s.mu.Lock()
	return s.log
}

// Relies on client first calling Prepare to lock.
func (s *Server) Commit(newLog []byte) {
	s.log = newLog
	s.mu.Unlock()
}

func MakeServer() *Server {
	return &Server{mu: new(sync.Mutex)}
}

func (s *Server) Start(me grove_ffi.Address) {
	handlers := make(map[uint64]func([]byte, *[]byte))

	handlers[shared.RpcPrepare] =
		func(enc_args []byte, enc_reply *[]byte) {
			*enc_reply = s.Prepare()
		}

	handlers[shared.RpcCommit] =
		func(enc_args []byte, enc_reply *[]byte) {
			s.Commit(enc_args)
		}

	urpc.MakeServer(handlers).Serve(me)
}
