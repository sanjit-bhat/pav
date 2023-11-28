package full2

import (
	"github.com/mit-pdos/gokv/grove_ffi"
	"github.com/mit-pdos/gokv/urpc"
	"sync"
)

type Server struct {
	log  []*msgT
	lock *sync.Mutex
}

func (s *Server) Put(m *msgT) {
	s.lock.Lock()
	s.log = append(s.log, m)
	s.lock.Unlock()
}

func (s *Server) Get() []*msgT {
	s.lock.Lock()
	ret := make([]*msgT, len(s.log))
	copy(ret, s.log)
	s.lock.Unlock()
	return ret
}

func MakeServer() *Server {
	s := &Server{}
	s.log = make([]*msgT, 0)
	s.lock = new(sync.Mutex)
	return s
}

func (s *Server) Start(me grove_ffi.Address) {
	handlers := make(map[uint64]func([]byte, *[]byte))

	handlers[rpcPut] =
		func(enc_args []byte, enc_reply *[]byte) {
			m, _ := decodeMsgT(enc_args)
			s.Put(m)
		}

	handlers[rpcGet] =
		func(enc_args []byte, enc_reply *[]byte) {
			sl := s.Get()
			*enc_reply = encodeSliceMsgT(sl)
		}

	urpc.MakeServer(handlers).Serve(me)
}
