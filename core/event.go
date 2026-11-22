package core

import (
	"container/heap"
	"fmt"
	"math/rand"
	"sort"
)

// Event is one scheduled action in the deterministic event queue.
type Event struct {
	Time      int64
	Seq       uint64
	Periodic  bool // recurring timer (hello/refresh/aging), not counted as convergence work
	Desc      string
	Fn        func()
	cancelled bool
}

func (e *Event) Cancel() { e.cancelled = true }

type eventHeap []*Event

func (h eventHeap) Len() int { return len(h) }
func (h eventHeap) Less(i, j int) bool {
	if h[i].Time != h[j].Time {
		return h[i].Time < h[j].Time
	}
	return h[i].Seq < h[j].Seq
}
func (h eventHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *eventHeap) Push(x interface{}) { *h = append(*h, x.(*Event)) }
func (h *eventHeap) Pop() interface{} {
	old := *h
	n := len(old)
	e := old[n-1]
	*h = old[:n-1]
	return e
}

// Link is a point-to-point physical link between two interfaces.
type Link struct {
	ID    int
	A, B  *Interface
	Cost  int
	Delay int64
	Up    bool
}

// Other returns the interface on the other end.
func (l *Link) Other(ifc *Interface) *Interface {
	if ifc == l.A {
		return l.B
	}
	return l.A
}

// Interface is one router interface on a point-to-point link.
type Interface struct {
	ID            int
	R             *Router
	Link          *Link
	Area          AreaID
	MTU           int
	Nbr           *Neighbor
	NbrHelloTimer *Event
}

// Up reports whether the interface is operational.
func (ifc *Interface) Up() bool { return ifc.Link.Up }

// AreaConf describes area-level configuration.
type AreaConf struct {
	Stub        bool
	TotallyStub bool
}

// World is the whole simulation: routers, links, and the event queue.
type World struct {
	Now     int64
	seq     uint64
	q       eventHeap
	Routers map[RouterID]*Router
	Links   []*Link
	VLs     []*VLink
	Areas   map[AreaID]*AreaConf
	Rng     *rand.Rand
	Cfg     Config

	LastChange         int64 // time of last topology-level change (convergence detection)
	EventsProcessed    int64 // total events processed
	NonPeriodicPending int64 // queued non-periodic events
	WorkEvents         int64 // non-periodic events processed (convergence work)
	ChangeLog          []string
}

// NewWorld creates an empty world.
func NewWorld(seed int64, cfg Config) *World {
	w := &World{
		Routers: make(map[RouterID]*Router),
		Areas:   make(map[AreaID]*AreaConf),
		Rng:     rand.New(rand.NewSource(seed)),
		Cfg:     cfg,
	}
	return w
}

// MarkChange records a state change at the current time.
func (w *World) MarkChange() { w.LastChange = w.Now }

// Schedule inserts an event delay ticks from now.
func (w *World) Schedule(delay int64, periodic bool, desc string, fn func()) *Event {
	w.seq++
	e := &Event{Time: w.Now + delay, Seq: w.seq, Periodic: periodic, Desc: desc, Fn: fn}
	heap.Push(&w.q, e)
	if !periodic {
		w.NonPeriodicPending++
	}
	return e
}

// Pending reports the number of queued events.
func (w *World) Pending() int { return len(w.q) }

// Step processes the next event. Returns false if the queue is empty.
func (w *World) Step() bool {
	for len(w.q) > 0 {
		e := heap.Pop(&w.q).(*Event)
		if e.cancelled {
			if !e.Periodic {
				w.NonPeriodicPending--
			}
			continue
		}
		w.Now = e.Time
		w.EventsProcessed++
		if !e.Periodic {
			w.NonPeriodicPending--
			w.WorkEvents++
		}
		e.Fn()
		return true
	}
	return false
}

// PeekTime returns the time of the next event, or -1.
func (w *World) PeekTime() int64 {
	for len(w.q) > 0 {
		if w.q[0].cancelled {
			heap.Pop(&w.q)
			continue
		}
		return w.q[0].Time
	}
	return -1
}

// RunQuiescent processes events until the network has converged: no
// non-periodic (protocol-work) events remain and no topology-level state has
// changed for StableWindow ticks. It returns the number of convergence-work
// events processed and the convergence time in ticks.
func (w *World) RunQuiescent() (events int64, convTime int64) {
	start := w.Now
	startWork := w.WorkEvents
	for {
		t := w.PeekTime()
		if t < 0 {
			break
		}
		if w.NonPeriodicPending == 0 && t > w.LastChange+w.Cfg.StableWindow {
			break
		}
		w.Step()
	}
	return w.WorkEvents - startWork, w.LastChange - start
}

// SortedRouters returns routers ordered by id (deterministic iteration).
func (w *World) SortedRouters() []*Router {
	rs := make([]*Router, 0, len(w.Routers))
	for _, r := range w.Routers {
		rs = append(rs, r)
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
	return rs
}

// sendPacket delivers a packet over a link after the link delay.
func (w *World) sendPacket(link *Link, from *Interface, pkt *Packet, periodic bool) {
	if !link.Up {
		return
	}
	w.Schedule(link.Delay, periodic, fmt.Sprintf("pkt %s L%d", pktTypeName(pkt.Type), link.ID), func() {
		if !link.Up {
			return
		}
		dst := link.Other(from)
		dst.R.handlePacket(dst, pkt)
	})
}

// sendPacketVL delivers a unicast packet across a virtual link.
func (w *World) sendPacketVL(vl *VLink, from RouterID, pkt *Packet, periodic bool) {
	w.Schedule(3, periodic, fmt.Sprintf("pkt %s VL%d", pktTypeName(pkt.Type), vl.ID), func() {
		r := w.Routers[vl.Other(from)]
		if r == nil {
			return
		}
		n := r.vlNeighbor(vl)
		if n == nil || !n.VLUp {
			return
		}
		r.handlePacketVL(vl, pkt)
	})
}

// SetLinkUp brings a link up or down and notifies both endpoints.
func (w *World) SetLinkUp(l *Link, up bool) {
	if l.Up == up {
		return
	}
	l.Up = up
	w.MarkChange()
	w.ChangeLog = append(w.ChangeLog, fmt.Sprintf("t=%d link %d (%s<->%s) up=%v",
		w.Now, l.ID, IDStr(l.A.R.ID), IDStr(l.B.R.ID), up))
	for _, ifc := range []*Interface{l.A, l.B} {
		if up {
			ifc.R.ifaceUp(ifc)
		} else {
			ifc.R.ifaceDown(ifc)
		}
	}
}

// SetLinkCost changes a link cost and triggers re-origination at both ends.
func (w *World) SetLinkCost(l *Link, cost int) {
	if l.Cost == cost {
		return
	}
	l.Cost = cost
	w.MarkChange()
	w.ChangeLog = append(w.ChangeLog, fmt.Sprintf("t=%d link %d cost=%d", w.Now, l.ID, cost))
	if l.Up {
		l.A.R.originateRouterLSA(l.A.Area)
		l.B.R.originateRouterLSA(l.B.Area)
	}
}
