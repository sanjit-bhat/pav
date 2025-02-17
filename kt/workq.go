package kt

import (
	"sync"
)

type Work struct {
	done bool
	Req  *WQReq
	Resp *WQResp
}

type WorkQ struct {
	mu         *sync.Mutex
	work       []*Work
	condCli    *sync.Cond
	condWorker *sync.Cond
}

func (wq *WorkQ) Do(r *Work) {
	wq.mu.Lock()
	wq.work = append(wq.work, r)
	wq.condWorker.Signal()

	for !r.done {
		wq.condCli.Wait()
	}
	wq.mu.Unlock()
}

func (wq *WorkQ) DoBatch(rs []*Work) {
	wq.mu.Lock()
	wq.work = append(wq.work, rs...)
	wq.condWorker.Signal()

	rsLen := len(rs)
	for !rs[rsLen-1].done {
		wq.condCli.Wait()
	}
	wq.mu.Unlock()
}

func (wq *WorkQ) Get() []*Work {
	wq.mu.Lock()
	for wq.work == nil {
		wq.condWorker.Wait()
	}

	maxWork := 100_000
	var work []*Work
	if len(wq.work) > maxWork {
		work = wq.work[:maxWork]
		wq.work = wq.work[maxWork:]
	} else {
		work = wq.work
		wq.work = nil
	}
	wq.mu.Unlock()
	return work
}

func (wq *WorkQ) Finish(work []*Work) {
	wq.mu.Lock()
	for _, x := range work {
		x.done = true
	}
	wq.mu.Unlock()
	wq.condCli.Broadcast()
}

func NewWorkQ() *WorkQ {
	mu := new(sync.Mutex)
	condCli := sync.NewCond(mu)
	condWork := sync.NewCond(mu)
	return &WorkQ{mu: mu, condCli: condCli, condWorker: condWork}
}
