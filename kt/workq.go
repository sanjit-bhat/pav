package kt

import (
	"sync"
)

type Work struct {
	mu   *sync.Mutex
	cond *sync.Cond
	done bool
	Req  *WQReq
	Resp *WQResp
}

type WorkQ struct {
	mu   *sync.Mutex
	work []*Work
	cond *sync.Cond
}

func (w *Work) Finish() {
	w.mu.Lock()
	w.done = true
	w.cond.Signal()
	w.mu.Unlock()
}

func (wq *WorkQ) Do(req *WQReq) *WQResp {
	w := &Work{mu: new(sync.Mutex), Req: req}
	w.cond = sync.NewCond(w.mu)

	wq.mu.Lock()
	wq.work = append(wq.work, w)
	wq.cond.Signal()
	wq.mu.Unlock()

	w.mu.Lock()
	for !w.done {
		w.cond.Wait()
	}
	w.mu.Unlock()

	return w.Resp
}

// DoBatch is unverified. it's only used as a benchmark helper for
// unmeasured batch puts.
func (wq *WorkQ) DoBatch(reqs []*WQReq) {
	works := make([]*Work, len(reqs))
	for i, req := range reqs {
		works[i] = &Work{mu: new(sync.Mutex), Req: req}
		works[i].cond = sync.NewCond(works[i].mu)
	}

	wq.mu.Lock()
	wq.work = append(wq.work, works...)
	wq.cond.Signal()
	wq.mu.Unlock()

	n := len(works)
	for i := 0; i < n; i++ {
		w := works[n - 1 - i]

		w.mu.Lock()
		for !w.done {
			w.cond.Wait()
		}
		w.mu.Unlock()
	}
}

func (wq *WorkQ) Get() []*Work {
	wq.mu.Lock()
	for wq.work == nil {
		wq.cond.Wait()
	}

	work := wq.work
	wq.work = nil
	wq.mu.Unlock()
	return work
}

func NewWorkQ() *WorkQ {
	mu := new(sync.Mutex)
	cond := sync.NewCond(mu)
	return &WorkQ{mu: mu, cond: cond}
}
