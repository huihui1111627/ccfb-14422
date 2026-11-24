package ospf

import (
	"fmt"
)

// ---- Interface state machine (RFC 2328 section 9.3) -----------------------
//
// Only the states relevant to point-to-point and virtual links are modelled.
// Broadcast interfaces are treated as point-to-point in this simulation since
// the sea-area backhaul is a mesh of dedicated radio links; the DR/BDR
// machinery is therefore intentionally absent and documented.

type IfState uint8

const (
	IfDown IfState = iota
	IfLoopback
	IfWaiting
	IfPointToPoint
	IfDR
	IfBackup
	IfDROther
)

func (s IfState) String() string {
	switch s {
	case IfDown:
		return "Down"
	case IfLoopback:
		return "Loopback"
	case IfWaiting:
		return "Waiting"
	case IfPointToPoint:
		return "Point-to-Point"
	case IfDR:
		return "DR"
	case IfBackup:
		return "Backup"
	case IfDROther:
		return "DROther"
	}
	return "?"
}

// InterfaceEvent is the interface event set of RFC 2328 section 9.2, limited
// to those reachable for active point-to-point links.
type InterfaceEvent int

const (
	IfEventUp InterfaceEvent = iota + 1
	IfEventDown
	IfEventUnloop
	IfEventWaitTimer
	IfEventBackupSeen
	IfEventNoBackupSeen
	IfEventNbrChange
)

func (e InterfaceEvent) String() string {
	switch e {
	case IfEventUp:
		return "InterfaceUp"
	case IfEventDown:
		return "InterfaceDown"
	case IfEventUnloop:
		return "UnloopInd"
	case IfEventWaitTimer:
		return "WaitTimer"
	case IfEventBackupSeen:
		return "BackupSeen"
	case IfEventNoBackupSeen:
		return "NoBackupSeen"
	case IfEventNbrChange:
		return "NeighborChange"
	}
	return "?"
}

// Interface is a router-local view of one running OSPF interface. It owns the
// hello timers and the per-neighbour state machines attached to it.
type Interface struct {
	Name            string
	Area            uint32
	State           IfState
	Mtu             int
	Cost            uint16
	HelloTimer      int64 // virtual ms period
	DeadMult        int   // dead interval = HelloTimer * DeadMult
	HelloIntervalMs int64
	DeadIntervalMs  int64
	// Nbrs are the known neighbours on this interface, keyed by router ID.
	Nbrs map[uint32]*Neighbour
	// Peer is the router at the other end of a point-to-point or virtual link.
	Peer uint32
	// Virtual links are logical interfaces in the backbone whose packets are
	// tunnelled through a transit area.
	Virtual  bool
	Transit  uint32
	HelloDue int64
	Options  uint8
	// HelloGen invalidates the previous hello timer when the interface is
	// restarted.
	HelloGen uint64
}

// NewInterface creates an interface in the Down state.
func NewInterface(name string, area uint32, mtu int, cost uint16, helloMs int64, deadMult int) *Interface {
	return &Interface{
		Name:            name,
		Area:            area,
		State:           IfDown,
		Mtu:             mtu,
		Cost:            cost,
		HelloIntervalMs: helloMs,
		DeadIntervalMs:  helloMs * int64(deadMult),
		DeadMult:        deadMult,
		Nbrs:            map[uint32]*Neighbour{},
	}
}

// ---- Neighbour state machine (RFC 2328 section 10.3) -----------------------

type NeighbourEvent int

const (
	NbrEventHelloReceived NeighbourEvent = iota + 1
	NbrEvent2WayReceived
	NbrEventNegotiationDone
	NbrEventExchangeDone
	NbrEventLoadingDone
	NbrEventBadLSReq
	NbrEventSeqNumberMismatch
	NbrEvent1WayReceived
	NbrEventKillNbr
	NbrEventInactivityTimer
	NbrEventLLDown
	// Events internal to this implementation.
	NbrEventAdjOK
	NbrEventAdjFail
)

func (e NeighbourEvent) String() string {
	switch e {
	case NbrEventHelloReceived:
		return "HelloReceived"
	case NbrEvent2WayReceived:
		return "2-WayReceived"
	case NbrEventNegotiationDone:
		return "NegotiationDone"
	case NbrEventExchangeDone:
		return "ExchangeDone"
	case NbrEventLoadingDone:
		return "LoadingDone"
	case NbrEventBadLSReq:
		return "BadLSReq"
	case NbrEventSeqNumberMismatch:
		return "SeqNumberMismatch"
	case NbrEvent1WayReceived:
		return "1-WayReceived"
	case NbrEventKillNbr:
		return "KillNbr"
	case NbrEventInactivityTimer:
		return "InactivityTimer"
	case NbrEventLLDown:
		return "LLDown"
	case NbrEventAdjOK:
		return "AdjOK"
	case NbrEventAdjFail:
		return "AdjFail"
	}
	return "?"
}

// ServerState is the voluntary stopping of the protocol on a router so the
// test harness can exercise interface down events.
type ServerState int

const (
	SrvUp ServerState = iota
	SrvShutdown
)

// Neighbour holds the per-neighbour protocol variables.
type Neighbour struct {
	RouterID uint32
	State    NbrState
	Priority uint8
	Options  uint8
	// DD sequence negotiation.
	DDSeq       uint32
	LastAckedDD uint32
	Master      bool
	// Exchange/Loading bookkeeping.
	DDHeads     map[LSAKey]LSAHead
	DDList      []LSAHead // ordered list still to be sent
	DDIndex     int
	LoadingKeys []LSAKey
	// LSR retransmission and LSU retransmission lists.
	LSRequests   map[LSAKey]int64 // key -> retry deadline
	LSRetransmit map[LSAKey]*LSA  // LSAs awaiting acknowledgement
	// DB summary: keys already sent in DD
	DBSumSent map[LSAKey]bool
	// MtuDisagreement records the failure required by requirement 2.
	MtuDisagreement bool
	MtuLocal        int
	MtuRemote       int
	// AdminShutdown marks a neighbour that cannot form an adjacency because
	// an administrator took the remote end down.
	LastHello int64
	// StateSince is the virtual time of the last state transition.
	StateSince int64
	// Stats.
	HellosRecv int
	HellosSent int
	// area is the area of the interface this neighbour lives on.
	area uint32
	// InactivityGen and timerArmed/TimerGen let stale timers become no-ops
	// without removing entries from the event queue.
	InactivityGen uint64
	timerArmed    bool
	TimerGen      uint64
	// DD retransmission bookkeeping.
	LastDDBody      []byte
	LastDDSeq       uint32
	LastDDAt        int64
	SlaveSentFinal  bool
	MasterSentFinal bool
}

// Neighbour initialisation on a new Hello.
func (i *Interface) newNeighbour(rid uint32, now int64) *Neighbour {
	n := &Neighbour{
		RouterID:     rid,
		area:         i.Area,
		State:        Down,
		DDHeads:      map[LSAKey]LSAHead{},
		LSRequests:   map[LSAKey]int64{},
		LSRetransmit: map[LSAKey]*LSA{},
		DBSumSent:    map[LSAKey]bool{},
		StateSince:   now,
		LastHello:    now,
	}
	i.Nbrs[rid] = n
	return n
}

// ---- Transition tables ----------------------------------------------------

// NbrTransition describes an allowed neighbour state transition.
type NbrTransition struct {
	From, To NbrState
	Event    NeighbourEvent
}

// NbrEventTable is the published event/state table used by the verifier. Each
// entry lists the states a neighbour may enter when the event is delivered in
// the given state, plus the possibility of "no change".
type EventRule struct {
	State  NbrState
	Event  NeighbourEvent
	Result []NbrState
}

var eventTable = []EventRule{
	{Down, NbrEventHelloReceived, []NbrState{Init, Down}},
	{Down, NbrEvent1WayReceived, []NbrState{Down, Init}},
	{Down, NbrEvent2WayReceived, []NbrState{Down, TwoWay, Init}},
	{Down, NbrEventNegotiationDone, []NbrState{Down, ExStart}},
	{Down, NbrEventExchangeDone, []NbrState{Down}},
	{Down, NbrEventLoadingDone, []NbrState{Down}},
	{Down, NbrEventBadLSReq, []NbrState{Down, ExStart}},
	{Down, NbrEventSeqNumberMismatch, []NbrState{Down, ExStart}},
	{Down, NbrEventKillNbr, []NbrState{Down}},
	{Down, NbrEventInactivityTimer, []NbrState{Down}},
	{Down, NbrEventLLDown, []NbrState{Down, Init}},

	{Init, NbrEventHelloReceived, []NbrState{Init}},
	{Init, NbrEvent1WayReceived, []NbrState{Init}},
	{Init, NbrEvent2WayReceived, []NbrState{TwoWay, ExStart, Init}},
	{Init, NbrEventNegotiationDone, []NbrState{Init, ExStart}},
	{Init, NbrEventExchangeDone, []NbrState{Init}},
	{Init, NbrEventLoadingDone, []NbrState{Init}},
	{Init, NbrEventBadLSReq, []NbrState{Init, Down, ExStart}},
	{Init, NbrEventSeqNumberMismatch, []NbrState{Init, ExStart}},
	{Init, NbrEventKillNbr, []NbrState{Down, Init}},
	{Init, NbrEventInactivityTimer, []NbrState{Down, Init}},
	{Init, NbrEventLLDown, []NbrState{Down, Init}},

	{TwoWay, NbrEventHelloReceived, []NbrState{TwoWay}},
	{TwoWay, NbrEvent1WayReceived, []NbrState{Init, TwoWay}},
	{TwoWay, NbrEvent2WayReceived, []NbrState{TwoWay, ExStart}},
	{TwoWay, NbrEventNegotiationDone, []NbrState{TwoWay, ExStart}},
	{TwoWay, NbrEventExchangeDone, []NbrState{TwoWay, Full, Exchange}},
	{TwoWay, NbrEventLoadingDone, []NbrState{TwoWay, Full}},
	{TwoWay, NbrEventBadLSReq, []NbrState{TwoWay, Down, ExStart}},
	{TwoWay, NbrEventSeqNumberMismatch, []NbrState{TwoWay, ExStart}},
	{TwoWay, NbrEventKillNbr, []NbrState{Down, TwoWay}},
	{TwoWay, NbrEventInactivityTimer, []NbrState{Down, TwoWay}},
	{TwoWay, NbrEventLLDown, []NbrState{Down, TwoWay}},

	{ExStart, NbrEventHelloReceived, []NbrState{ExStart}},
	{ExStart, NbrEvent1WayReceived, []NbrState{Init, ExStart}},
	{ExStart, NbrEvent2WayReceived, []NbrState{ExStart, TwoWay}},
	{ExStart, NbrEventNegotiationDone, []NbrState{Exchange, ExStart}},
	{ExStart, NbrEventExchangeDone, []NbrState{ExStart, Full, Exchange}},
	{ExStart, NbrEventLoadingDone, []NbrState{ExStart, Full}},
	{ExStart, NbrEventBadLSReq, []NbrState{ExStart, Down, ExStart}},
	{ExStart, NbrEventSeqNumberMismatch, []NbrState{ExStart}},
	{ExStart, NbrEventKillNbr, []NbrState{Down, ExStart}},
	{ExStart, NbrEventInactivityTimer, []NbrState{Down, ExStart}},
	{ExStart, NbrEventLLDown, []NbrState{Down, ExStart}},

	{Exchange, NbrEventHelloReceived, []NbrState{Exchange}},
	{Exchange, NbrEvent1WayReceived, []NbrState{Init, Exchange}},
	{Exchange, NbrEvent2WayReceived, []NbrState{Exchange, TwoWay}},
	{Exchange, NbrEventNegotiationDone, []NbrState{Exchange}},
	{Exchange, NbrEventExchangeDone, []NbrState{Loading, Full, Exchange}},
	{Exchange, NbrEventLoadingDone, []NbrState{Exchange, Full}},
	{Exchange, NbrEventBadLSReq, []NbrState{Exchange, Down, ExStart}},
	{Exchange, NbrEventSeqNumberMismatch, []NbrState{Exchange, ExStart}},
	{Exchange, NbrEventKillNbr, []NbrState{Down, Exchange}},
	{Exchange, NbrEventInactivityTimer, []NbrState{Down, Exchange}},
	{Exchange, NbrEventLLDown, []NbrState{Down, Exchange}},

	{Loading, NbrEventHelloReceived, []NbrState{Loading}},
	{Loading, NbrEvent1WayReceived, []NbrState{Init, Loading}},
	{Loading, NbrEvent2WayReceived, []NbrState{Loading, TwoWay}},
	{Loading, NbrEventNegotiationDone, []NbrState{Loading}},
	{Loading, NbrEventExchangeDone, []NbrState{Loading, Full}},
	{Loading, NbrEventLoadingDone, []NbrState{Full, Loading}},
	{Loading, NbrEventBadLSReq, []NbrState{Loading, Down, ExStart}},
	{Loading, NbrEventSeqNumberMismatch, []NbrState{Loading, ExStart}},
	{Loading, NbrEventKillNbr, []NbrState{Down, Loading}},
	{Loading, NbrEventInactivityTimer, []NbrState{Down, Loading}},
	{Loading, NbrEventLLDown, []NbrState{Down, Loading}},

	{Full, NbrEventHelloReceived, []NbrState{Full}},
	{Full, NbrEvent1WayReceived, []NbrState{Init, Full}},
	{Full, NbrEvent2WayReceived, []NbrState{Full, TwoWay}},
	{Full, NbrEventNegotiationDone, []NbrState{Full}},
	{Full, NbrEventExchangeDone, []NbrState{Full}},
	{Full, NbrEventLoadingDone, []NbrState{Full}},
	{Full, NbrEventBadLSReq, []NbrState{Full, Down, ExStart}},
	{Full, NbrEventSeqNumberMismatch, []NbrState{Full, ExStart}},
	{Full, NbrEventKillNbr, []NbrState{Down, Full}},
	{Full, NbrEventInactivityTimer, []NbrState{Down, Full}},
	{Full, NbrEventLLDown, []NbrState{Down, Full}},

	// AdjOK is accepted from every state; it only advances TwoWay.
	// AdjFail is only meaningful from ExStart and above.
	{Down, NbrEventAdjOK, []NbrState{Down}},
	{Down, NbrEventAdjFail, []NbrState{TwoWay, Down}},
	{Init, NbrEventAdjOK, []NbrState{Init}},
	{Init, NbrEventAdjFail, []NbrState{TwoWay, Init}},
	{TwoWay, NbrEventAdjOK, []NbrState{ExStart, TwoWay}},
	{TwoWay, NbrEventAdjFail, []NbrState{TwoWay, TwoWay}},
	{ExStart, NbrEventAdjOK, []NbrState{TwoWay, ExStart}},
	{ExStart, NbrEventAdjFail, []NbrState{TwoWay, ExStart}},
	{Exchange, NbrEventAdjOK, []NbrState{TwoWay, Exchange}},
	{Exchange, NbrEventAdjFail, []NbrState{TwoWay, Exchange}},
	{Loading, NbrEventAdjOK, []NbrState{TwoWay, Loading}},
	{Loading, NbrEventAdjFail, []NbrState{TwoWay, Loading}},
	{Full, NbrEventAdjOK, []NbrState{TwoWay, Full}},
	{Full, NbrEventAdjFail, []NbrState{TwoWay, Full}},
}

// EventAllowedStates returns the permitted result states for the event in the
// given state, or nil when the event is not part of the table.
func EventAllowedStates(st NbrState, ev NeighbourEvent) []NbrState {
	for _, r := range eventTable {
		if r.State == st && r.Event == ev {
			return r.Result
		}
	}
	return nil
}

// ValidateTransition checks a transition record against the published table.
func ValidateTransition(rec TransitionRecord) error {
	allowed := EventAllowedStates(rec.From, rec.Event)
	if allowed == nil {
		return fmt.Errorf("event %s not defined in state %s", rec.Event, rec.From)
	}
	for _, s := range allowed {
		if s == rec.To {
			return nil
		}
	}
	return fmt.Errorf("illegal: %s --%s--> %s", rec.From, rec.Event, rec.To)
}

// TransitionRecord is what the state machine appends to the audit log.
type TransitionRecord struct {
	Router uint32
	Nbr    uint32
	From   NbrState
	Event  NeighbourEvent
	To     NbrState
	At     int64
}
