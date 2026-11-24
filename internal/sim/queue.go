// Package sim contains the deterministic event engine and the weather driven
// network model that the OSPF routers run inside.
package sim

import "container/heap"

// Event is one action scheduled at a virtual millisecond timestamp. Events
// with the same timestamp run in insertion order, which makes the whole
// simulation reproducible from the seed and the topology alone.
type Event struct {
	At  int64
	Seq int64
	Fn  func()
}

type eventHeap []*Event

func (h eventHeap) Len() int { return len(h) }
func (h eventHeap) Less(i, j int) bool {
	if h[i].At != h[j].At {
		return h[i].At < h[j].At
	}
	return h[i].Seq < h[j].Seq
}
func (h eventHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *eventHeap) Push(x any)   { *h = append(*h, x.(*Event)) }
func (h *eventHeap) Pop() any {
	old := *h
	n := len(old)
	e := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	return e
}

// Queue is a single-threaded, fully ordered event queue.
type Queue struct {
	h   eventHeap
	seq int64
}

func NewQueue() *Queue {
	q := &Queue{}
	heap.Init(&q.h)
	return q
}

// Push schedules fn at absolute virtual time at.
func (q *Queue) Push(at int64, fn func()) {
	if at < 0 {
		at = 0
	}
	q.seq++
	heap.Push(&q.h, &Event{At: at, Seq: q.seq, Fn: fn})
}

// Len is the number of pending events.
func (q *Queue) Len() int { return len(q.h) }

// PeekAt returns the timestamp of the next event and whether one exists.
func (q *Queue) PeekAt() (int64, bool) {
	if len(q.h) == 0 {
		return 0, false
	}
	return q.h[0].At, true
}

// Pop removes and returns the next event.
func (q *Queue) Pop() *Event {
	if len(q.h) == 0 {
		return nil
	}
	return heap.Pop(&q.h).(*Event)
}

// Cancel marks an event as cancelled by wrapping a comparison predicate. For
// the simulations here it is enough to skip cancelled events, so callers use
// a generation counter instead of removing entries from the heap.
