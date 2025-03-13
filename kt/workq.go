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

// DoBatch is unverified. it's only used as a benchmark helper for
// unmeasured batch puts.
func (wq *WorkQ) DoBatch(r []*Work) {
	wq.mu.Lock()
	wq.work = append(wq.work, r...)
	wq.condWorker.Signal()

	// invariant: forall i < j, if work[j].done, then work[i].done.
	// in pav, preserved by only having one worker that does:
	//
	//  w := wq.Get()
	//  ...
	//  wq.Finish(w)
	rLen := len(r)
	for !r[rLen-1].done {
		wq.condCli.Wait()
	}
	wq.mu.Unlock()
}

func (wq *WorkQ) Get() []*Work {
	wq.mu.Lock()
	for wq.work == nil {
		wq.condWorker.Wait()
	}

	work := wq.work
	wq.work = nil
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
