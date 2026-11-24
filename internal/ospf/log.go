package ospf

import (
	"fmt"
	"sort"
)

// LSARec aggregates per-advertisement counters across the whole simulation.
type LSARec struct {
	Key           LSAKey
	Type          LSAType
	AdvRtr        uint32
	Originated    int
	Flooded       int
	Retransmitted int
	Received      int
	StaleReplied  int
	MaxAgeFlushed int
	Refreshed     int
}

// Metrics is a shared, single-threaded counter store owned by the simulator.
// All routers write into it; snapshots are only taken from the simulation
// goroutine, so no locking is required.
type Metrics struct {
	LSAs           map[LSAKey]*LSARec
	Sent           map[uint8]int
	Recv           map[uint8]int
	Dropped        map[string]int
	SPFRuns        int
	SPFIncr        int
	SPFFull        int
	SPFTouched     int
	SPFFullTouched int
	Transitions    int
}

func NewMetrics() *Metrics {
	return &Metrics{
		LSAs:    map[LSAKey]*LSARec{},
		Sent:    map[uint8]int{},
		Recv:    map[uint8]int{},
		Dropped: map[string]int{},
	}
}

func (m *Metrics) rec(k LSAKey) *LSARec {
	r := m.LSAs[k]
	if r == nil {
		r = &LSARec{Key: k, Type: k.Type, AdvRtr: k.AdvRtr}
		m.LSAs[k] = r
	}
	return r
}

func (m *Metrics) Originated(l *LSA)    { m.rec(l.Key()).Originated++ }
func (m *Metrics) Flooded(l *LSA)       { m.rec(l.Key()).Flooded++ }
func (m *Metrics) Retransmitted(l *LSA) { m.rec(l.Key()).Retransmitted++ }
func (m *Metrics) Received(l *LSA)      { m.rec(l.Key()).Received++ }
func (m *Metrics) StaleReplied(l *LSA)  { m.rec(l.Key()).StaleReplied++ }
func (m *Metrics) Flushed(l *LSA)       { m.rec(l.Key()).MaxAgeFlushed++ }
func (m *Metrics) Refreshed(l *LSA)     { m.rec(l.Key()).Refreshed++ }

func (m *Metrics) Drop(reason string) { m.Dropped[reason]++ }

// LSASorted returns the counters ordered by type, advertising router, id.
func (m *Metrics) LSASorted() []*LSARec {
	out := make([]*LSARec, 0, len(m.LSAs))
	for _, r := range m.LSAs {
		cp := *r
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.AdvRtr != b.AdvRtr {
			return a.AdvRtr < b.AdvRtr
		}
		return a.Key.ID < b.Key.ID
	})
	return out
}

// EventKind classifies interesting protocol events for the live timeline.
type EventKind string

const (
	EvNbrChange EventKind = "nbr"
	EvFlood     EventKind = "flood"
	EvDrop      EventKind = "drop"
	EvSPF       EventKind = "spf"
	EvRoute     EventKind = "route"
	EvArea      EventKind = "area"
	EvWeather   EventKind = "weather"
	EvStuck     EventKind = "stuck"
)

// AuditEvent is a human readable timeline entry.
type AuditEvent struct {
	At     int64
	Kind   EventKind
	Router uint32
	Area   uint32
	Text   string
}

// Audit keeps the transition log (validated by the test harness) and a
// bounded ring of human readable events for the page.
type Audit struct {
	Transitions []TransitionRecord
	Events      []AuditEvent
	maxEvents   int
}

func NewAudit(maxEvents int) *Audit {
	if maxEvents <= 0 {
		maxEvents = 4000
	}
	return &Audit{maxEvents: maxEvents}
}

// Transition records a state change after validating it against the published
// event/state table. Illegal transitions are returned as an error so the
// harness can fail loudly instead of silently corrupting the log.
func (a *Audit) Transition(rec TransitionRecord) error {
	if err := ValidateTransition(rec); err != nil {
		return err
	}
	a.Transitions = append(a.Transitions, rec)
	return nil
}

func (a *Audit) Event(at int64, kind EventKind, rtr, area uint32, format string, args ...any) {
	e := AuditEvent{At: at, Kind: kind, Router: rtr, Area: area, Text: fmt.Sprintf(format, args...)}
	if len(a.Events) >= a.maxEvents {
		a.Events = a.Events[len(a.Events)-a.maxEvents/2:]
	}
	a.Events = append(a.Events, e)
}

// Recent returns the last n events.
func (a *Audit) Recent(n int) []AuditEvent {
	if n <= 0 || n > len(a.Events) {
		n = len(a.Events)
	}
	return append([]AuditEvent(nil), a.Events[len(a.Events)-n:]...)
}
