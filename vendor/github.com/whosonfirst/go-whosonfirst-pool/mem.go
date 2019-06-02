package pool

// https://github.com/SimonWaldherr/golang-examples/blob/2be89f3185aded00740a45a64e3c98855193b948/advanced/lifo.go

import (
	"sync"
	"sync/atomic"
)

type MemLIFOPool struct {
	nodes []Item
	count int64
	mutex *sync.Mutex
}

func NewMemLIFOPool() (LIFOPool, error) {

	mu := new(sync.Mutex)
	nodes := make([]Item, 0)

	pl := MemLIFOPool{
		mutex: mu,
		nodes: nodes,
		count: 0,
	}

	return &pl, nil
}

func (pl *MemLIFOPool) Length() int64 {

	pl.mutex.Lock()
	defer pl.mutex.Unlock()

	return atomic.LoadInt64(&pl.count)
}

func (pl *MemLIFOPool) Push(i Item) {

	pl.mutex.Lock()
	defer pl.mutex.Unlock()

	pl.nodes = append(pl.nodes[:pl.count], i)
	atomic.AddInt64(&pl.count, 1)
}

func (pl *MemLIFOPool) Pop() (Item, bool) {

	pl.mutex.Lock()
	defer pl.mutex.Unlock()

	if pl.count == 0 {
		return nil, false
	}

	atomic.AddInt64(&pl.count, -1)
	i := pl.nodes[pl.count]

	return i, true
}
