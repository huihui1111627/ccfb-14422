package ospf

import (
	"fmt"
	"sort"
)

// Protocol timer defaults in virtual milliseconds.
const (
	DefaultHelloMs        = 10_000
	DefaultDeadMul        = 4
	DefaultMTU            = 1500
	LSUChunk              = 4
	InitialDDSeq   uint32 = 0x00001000
	// RetransmitMs is the interval between retransmissions on a link whose
	// peer has not acknowledged a packet.
	RetransmitMs int64 = 5_000
)

// Router is a single OSPF process. Many routers live in one Go process and
// interact only through the callbacks the simulator installs, which keeps the
// whole system deterministic.
type Router struct {
	ID        uint32
	Name      string
	Areas     []uint32
	Topo      *Topo
	IsASBR    bool
	Externals []Prefix
	X, Y      float64

	areaDB map[uint32]map[LSAKey]*LSA
	// self and seqs are keyed by area because the same (type, id, adv) tuple
	// can appear independently in several areas: a router advertises its own
	// type 1 in each area it belongs to, and an ABR can summarise the same
	// prefix into more than one area.
	self map[uint32]map[LSAKey]*LSA
	seqs map[uint32]map[LSAKey]uint32

	Interfaces    map[string]*Interface
	ifOrder       []string
	VirInterfaces map[uint32]map[uint32]*Interface

	// SPF results, per area.
	spfArea  map[uint32]*SPFResult
	spfDirty map[uint32]bool
	// changes accumulates the router advertisement changes seen since the
	// last SPF run for each area, so the scheduler can apply them
	// incrementally instead of recomputing the whole graph.
	changes map[uint32][]lsaChange
	// routesDirty asks for the route table to be rebuilt without a shortest
	// path computation, used when only summaries or externals changed.
	routesDirty bool
	// lastDBChange is the virtual time of the most recent database install.
	lastDBChange int64
	// lastSPF records how the most recent run for an area was performed.
	lastSPF map[uint32]SPFStat
	Routes  []*Route

	// Injected services.
	Now      func() int64
	Schedule func(at int64, fn func())
	Send     func(linkID string, dst uint32, pkt *Packet, size int)
	LinkUp   func(linkID string) bool
	Metrics  *Metrics
	Audit    *Audit

	// Per-area link identity: peer router -> link ID on that area.
	linkTo map[uint32]string

	started bool
	// Periodic timers.
	refreshGen uint64
	// Ack bookkeeping, used by the verifier's flooding statistics.
	ackMatched  int
	ackMismatch int
}

// NewRouter builds a router from configuration and topology.
func NewRouter(rc *RouterConfig, topo *Topo, metrics *Metrics, audit *Audit) *Router {
	r := &Router{
		ID:            rc.ID,
		Name:          rc.Name,
		Topo:          topo,
		IsASBR:        rc.IsASBR,
		Externals:     append([]Prefix(nil), rc.Externals...),
		X:             rc.X,
		Y:             rc.Y,
		areaDB:        map[uint32]map[LSAKey]*LSA{},
		self:          map[uint32]map[LSAKey]*LSA{},
		seqs:          map[uint32]map[LSAKey]uint32{},
		Interfaces:    map[string]*Interface{},
		VirInterfaces: map[uint32]map[uint32]*Interface{},
		spfArea:       map[uint32]*SPFResult{},
		spfDirty:      map[uint32]bool{},
		changes:       map[uint32][]lsaChange{},
		lastSPF:       map[uint32]SPFStat{},
		linkTo:        map[uint32]string{},
		Metrics:       metrics,
		Audit:         audit,
	}
	r.Areas = topo.RouterAreas(rc.ID)
	return r
}

// AreaEnabled reports whether the router participates in the area.
func (r *Router) AreaEnabled(a uint32) bool {
	for _, x := range r.Areas {
		if x == a {
			return true
		}
	}
	return false
}

func (r *Router) db(area uint32) map[LSAKey]*LSA {
	d := r.areaDB[area]
	if d == nil {
		d = map[LSAKey]*LSA{}
		r.areaDB[area] = d
	}
	return d
}

// AreaDB returns a copy of every advertisement in one area, sorted.
func (r *Router) AreaDB(area uint32) []*LSA {
	d := r.areaDB[area]
	out := make([]*LSA, 0, len(d))
	for _, l := range d {
		out = append(out, l.Clone())
	}
	sort.Slice(out, func(i, j int) bool {
		return keyLess(out[i].Key(), out[j].Key())
	})
	return out
}

// Lookup returns the database entry for a key in an area.
func (r *Router) Lookup(area uint32, k LSAKey) *LSA { return r.areaDB[area][k] }

// DBSize returns the number of advertisements held for an area.
func (r *Router) DBSize(area uint32) int { return len(r.areaDB[area]) }

func keyLess(a, b LSAKey) bool {
	if a.Type != b.Type {
		return a.Type < b.Type
	}
	if a.ID != b.ID {
		return a.ID < b.ID
	}
	return a.AdvRtr < b.AdvRtr
}

// ---- Interface lifecycle -------------------------------------------------

// AddInterface registers a physical point-to-point interface bound to a link.
func (r *Router) AddInterface(name string, area uint32, mtu int, cost uint16, peer uint32) *Interface {
	i := NewInterface(name, area, mtu, cost, DefaultHelloMs, DefaultDeadMul)
	i.Peer = peer
	r.Interfaces[name] = i
	r.ifOrder = append(r.ifOrder, name)
	sort.Strings(r.ifOrder)
	r.linkTo[peer] = name
	return i
}

// AddVirtualInterface registers a virtual link interface in the backbone.
func (r *Router) AddVirtualInterface(transit, peer uint32, mtu int, cost uint16) *Interface {
	m := r.VirInterfaces[transit]
	if m == nil {
		m = map[uint32]*Interface{}
		r.VirInterfaces[transit] = m
	}
	i := NewInterface(fmt.Sprintf("vl-%s-%s", u32ip(transit), u32ip(peer)), 0, mtu, cost, DefaultHelloMs, DefaultDeadMul)
	i.Virtual = true
	i.Peer = peer
	i.Transit = transit
	m[peer] = i
	return i
}

// Start brings every interface up and originates the initial router LSAs.
func (r *Router) Start(now int64) {
	if r.started {
		return
	}
	r.started = true
	for _, name := range r.ifOrder {
		r.interfaceUp(name, now)
	}
	for _, trans := range sortedAreaKeys(r.VirInterfaces) {
		for _, peer := range sortedPeerKeys(r.VirInterfaces[trans]) {
			r.virtualUp(r.VirInterfaces[trans][peer], now)
		}
	}
	for _, a := range r.Areas {
		r.originateRouterLSA(a, now)
	}
	if r.IsASBR {
		r.originateExternals(now)
	}
	r.scheduleRefresh(now)
}

func sortedAreaKeys[T any](m map[uint32]T) []uint32 {
	out := make([]uint32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedNbrKeys(m map[uint32]*Neighbour) []uint32 {
	out := make([]uint32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedPeerKeys(m map[uint32]*Interface) []uint32 {
	out := make([]uint32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// interfaceUp is the InterfaceUp event (RFC 2328 section 9.3).
func (r *Router) interfaceUp(name string, now int64) {
	i := r.Interfaces[name]
	if i == nil || i.State != IfDown {
		return
	}
	i.State = IfPointToPoint
	i.HelloDue = now
	r.scheduleHello(i, now)
	r.originateRouterLSA(i.Area, now)
	r.Audit.Event(now, EvArea, r.ID, i.Area, "interface %s up (P2P, cost %d, mtu %d)", name, i.Cost, i.Mtu)
}

// interfaceDown is the InterfaceDown event.
func (r *Router) interfaceDown(name string, now int64) {
	i := r.Interfaces[name]
	if i == nil || i.State == IfDown {
		return
	}
	for _, n := range i.Nbrs {
		r.nbrEvent(i, n, NbrEventLLDown, now)
	}
	i.Nbrs = map[uint32]*Neighbour{}
	i.State = IfDown
	r.originateRouterLSA(i.Area, now)
	r.Audit.Event(now, EvArea, r.ID, i.Area, "interface %s down", name)
}

// virtualUp brings a virtual link interface into Point-to-Point.
func (r *Router) virtualUp(i *Interface, now int64) {
	if i.State != IfDown {
		return
	}
	i.State = IfPointToPoint
	r.scheduleHello(i, now)
	r.originateRouterLSA(0, now)
	r.Audit.Event(now, EvArea, r.ID, 0, "virtual link %s up (transit %s)", i.Name, u32ip(i.Transit))
}

// SetInterfaceCost changes the cost of a physical link.
func (r *Router) SetInterfaceCost(name string, cost uint16, now int64) {
	i := r.Interfaces[name]
	if i == nil || i.Cost == cost {
		return
	}
	i.Cost = cost
	r.originateRouterLSA(i.Area, now)
	r.Audit.Event(now, EvArea, r.ID, i.Area, "interface %s cost -> %d", name, cost)
}

// ---- Hello generation ----------------------------------------------------

func (r *Router) helloBody(i *Interface) HelloBody {
	h := HelloBody{
		HelloInterval:  uint16(i.HelloIntervalMs / 1000),
		DeadInterval:   uint16(i.DeadIntervalMs / 1000),
		Options:        r.areaOptions(i.Area),
		RouterPriority: 1,
		NetworkMask:    0xffffffff,
	}
	ids := make([]uint32, 0, len(i.Nbrs))
	for id := range i.Nbrs {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(a, b int) bool { return ids[a] < ids[b] })
	h.Neighbours = ids
	return h
}

func (r *Router) scheduleHello(i *Interface, now int64) {
	i.HelloGen++
	gen := i.HelloGen
	period := i.HelloIntervalMs
	var tick func(at int64)
	tick = func(at int64) {
		if i.HelloGen != gen || i.State == IfDown {
			return
		}
		r.sendHello(i, at)
		r.Schedule(at+period, func() { tick(at + period) })
	}
	r.Schedule(now+period, func() { tick(now + period) })
}

func (r *Router) sendHello(i *Interface, now int64) {
	if i.State == IfDown {
		return
	}
	body := MarshalHello(r.helloBody(i))
	r.Metrics.Sent[PktHello]++
	r.transmit(i, i.Peer, &Packet{Type: PktHello, Src: r.ID, SrcArea: i.Area, Body: body}, PacketSize(PktHello, len(body)))
}

// transmit hands a packet to the simulator.
func (r *Router) transmit(i *Interface, dst uint32, pkt *Packet, size int) {
	linkID := i.Name
	if i.Virtual {
		// Virtual links ride the routing table: the simulator resolves the
		// next hop through the transit area.
		linkID = "vl:" + i.Name
	}
	r.Send(linkID, dst, pkt, size)
}

// ---- Database Description ------------------------------------------------

// ddHeadsFor builds the next summary chunk and marks the keys as sent.
func (r *Router) ddHeadsFor(n *Neighbour) []LSAHead {
	db := r.areaDB[n.area]
	var keys []LSAKey
	for k := range db {
		if !n.DBSumSent[k] {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(a, b int) bool { return keyLess(keys[a], keys[b]) })
	if len(keys) > LSUChunk {
		keys = keys[:LSUChunk]
	}
	heads := make([]LSAHead, 0, len(keys))
	for _, k := range keys {
		l := db[k]
		n.DBSumSent[k] = true
		heads = append(heads, HeadOf(l.AgedCopy(r.Now())))
	}
	return heads
}

// hasMoreDD reports whether unsent database summaries remain.
func (r *Router) hasMoreDD(n *Neighbour) bool {
	for k := range r.areaDB[n.area] {
		if !n.DBSumSent[k] {
			return true
		}
	}
	return false
}

// areaOptions clears the E-bit for stub and totally stubby areas.
func (r *Router) areaOptions(area uint32) uint8 {
	if r.isStubArea(area) {
		return 0
	}
	return OptE
}

// AckStats exposes ack bookkeeping for diagnostics.
func (r *Router) AckStats() (matched, mismatch int) { return r.ackMatched, r.ackMismatch }
