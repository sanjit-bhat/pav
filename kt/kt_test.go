package kt

/*
benchmarking file. run with:
go test -bench=. -benchmem -benchtime=5s -cpuprofile=kt.prof ./kt
go tool pprof -http=localhost:4959 kt.test kt.prof
*/

import (
	"testing"
)

func BenchmarkPut(b *testing.B) {
	serv, _, _ := NewServer()

	uid := uint64(0)
	b.ResetTimer()
	for range b.N {
		serv.Put(uid, []byte("pk"))
		uid++
	}
}
