package sim

import (
	"math/rand"
	"sort"

	"backhaul/internal/ospf"
)

// Simulation wires the routers, the link layer and the weather script into a
// single deterministic event loop.
type Simulation struct {
	Seed      int64
	Q         *Queue
	Topo      *ospf.Topo
	Routers   map[uint32]*ospf.Router
	RouterIDs []uint32
	// Routing order is stable so snapshots and verifier output are stable.
	Weather []WeatherEvent
	Links   map[string]*LinkState
	Metrics *ospf.Metrics
	Audit   *ospf.Audit
	NowTick int64
	// rng is reserved for per-packet loss decisions in a future extension; the
	// replay uses the pre-generated weather script for determinism.
	rng      *rand.Rand
	disabled map[uint32]bool
	// wire queue: packets delivered with a deterministic per-link delay.
	packetsSent int
	packetsLost int
	packetsDup  int
	// DebugDrops prints the reason for unusual drops to stderr.
	N int
}

// Options configures a run.
type Options struct {
	Seed     int64
	Duration int64 // virtual milliseconds
	MeanGap  int64 // mean weather event spacing in ms
	// LossModel enables deterministic loss decisions derived from the seed.
	LossModel bool
	// WeatherUntil stops weather events before this time, leaving a quiet
	// tail so the network can settle for final verification.
	WeatherUntil int64
	AuditMax     int
}

// New builds a simulation with routers started and weather scheduled.
func New(topo *ospf.Topology, opt Options) (*Simulation, error) {
	t, err := ospf.BuildTopo(topo)
	if err != nil {
		return nil, err
	}
	q := NewQueue()
	metrics := ospf.NewMetrics()
	audit := ospf.NewAudit(opt.AuditMax)
	s := &Simulation{
		Seed:     opt.Seed,
		Q:        q,
		Topo:     t,
		Routers:  map[uint32]*ospf.Router{},
		Links:    map[string]*LinkState{},
		Metrics:  metrics,
		Audit:    audit,
		rng:      rand.New(rand.NewSource(opt.Seed ^ 0x5eed)),
		disabled: map[uint32]bool{},
	}
	for i := range topo.Routers {
		rc := &topo.Routers[i]
		r := ospf.NewRouter(rc, t, metrics, audit)
		s.Routers[r.ID] = r
		s.RouterIDs = append(s.RouterIDs, r.ID)
	}
	sort.Slice(s.RouterIDs, func(i, j int) bool { return s.RouterIDs[i] < s.RouterIDs[j] })
	// Build link states.
	for _, l := range t.Links {
		ls := &LinkState{ID: l.ID, Up: true, BaseCost: l.Cost, Cost: l.Cost, DelayMs: int64(l.Nominal)}
		if ls.DelayMs <= 0 {
			ls.DelayMs = 10
		}
		s.Links[l.ID] = ls
	}
	// Bind interfaces.
	for _, l := range t.Links {
		ra := s.Routers[l.A]
		rb := s.Routers[l.B]
		ra.AddInterface(l.ID, l.Area, l.MtuA, l.Cost, l.B)
		rb.AddInterface(l.ID, l.Area, l.MtuB, l.Cost, l.A)
	}
	// Virtual links: endpoints are ABRs in the backbone.
	for i := range t.Virtual {
		v := &t.Virtual[i]
		ra := s.Routers[v.A]
		rb := s.Routers[v.B]
		if ra != nil && rb != nil {
			ra.AddVirtualInterface(v.Transit, v.B, ospf.DefaultMTU, 65535)
			rb.AddVirtualInterface(v.Transit, v.A, ospf.DefaultMTU, 65535)
		}
	}
	// For every router, a transit-area SPF is needed to cost virtual links,
	// so make sure the transit area is one of its areas. A virtual link
	// endpoint always has a physical interface in the transit area; this is
	// enforced by the topology generator.
	links := make([]string, 0, len(t.Links))
	for _, l := range t.Links {
		links = append(links, l.ID)
	}
	sort.Strings(links)
	weatherEnd := opt.Duration
	if opt.WeatherUntil > 0 && opt.WeatherUntil < weatherEnd {
		weatherEnd = opt.WeatherUntil
	}
	s.Weather = GenerateWeather(opt.Seed, links, 0, weatherEnd, opt.MeanGap)
	// Inject services.
	for _, id := range s.RouterIDs {
		r := s.Routers[id]
		r.Now = func() int64 { return s.NowTick }
		r.Schedule = q.Push
		r.Send = s.send
		r.LinkUp = s.linkUp
	}
	return s, nil
}

// Start schedules the initial router startup.
func (s *Simulation) Start() {
	for _, id := range s.RouterIDs {
		r := s.Routers[id]
		s.Q.Push(1, func() { r.Start(s.NowTick) })
	}
	// Weather events are scheduled as-is.
	for _, e := range s.Weather {
		ev := e
		s.Q.Push(ev.At, func() { s.applyWeather(ev) })
	}
}

// send is the transmit callback installed on every router. It resolves the
// destination, applies weather loss/delay and schedules delivery.
func (s *Simulation) send(linkID string, dst uint32, pkt *ospf.Packet, size int) {
	now := s.NowTick
	src := pkt.Src
	switch {
	case len(linkID) > 3 && linkID[:3] == "vl:":
		s.sendVirtual(linkID[3:], src, dst, pkt, size, now)
		return
	}
	l := s.Topo.Links[linkID]
	if l == nil {
		s.Metrics.Drop("unknown-link")
		return
	}
	ls := s.Links[linkID]
	peer := l.Adjacent(src)
	if dst != 0 && dst != peer {
		s.Metrics.Drop("wrong-dst")
		return
	}
	if ls == nil || !ls.Up {
		s.Metrics.Drop("link-down")
		return
	}
	// MTU: a packet larger than the link's MTU is dropped. The asymmetry of
	// the two ends is exercised by the explicit DD MTU check.
	mtu := l.MTUFor(src)
	if size > mtu {
		s.Metrics.Drop("mtu")
		return
	}
	if s.lossDrops(ls, pkt, now) {
		s.packetsLost++
		s.Metrics.Drop("weather-loss")
		return
	}
	s.packetsSent++
	delay := ls.DelayMs
	if delay <= 0 {
		delay = 1
	}
	deliver := func() { s.deliver(peer, linkID, pkt) }
	s.Q.Push(now+delay, deliver)
}

// lossDrops decides deterministically whether a packet is lost.
func (s *Simulation) lossDrops(ls *LinkState, pkt *ospf.Packet, now int64) bool {
	if ls.Loss <= 0 {
		return false
	}
	// A hash-based decision keeps the replay independent of global RNG order.
	h := mix64(uint64(now) ^ uint64(pkt.Src)*0x9e3779b97f4a7c15 ^ uint64(ls.Loss*1000))
	return float64(h%10000)/100.0 < ls.Loss
}

func mix64(x uint64) uint64 {
	x ^= x >> 33
	x *= 0xff51afd7ed558ccd
	x ^= x >> 33
	x *= 0xc4ceb9fe1a85ec53
	x ^= x >> 33
	return x
}

// sendVirtual tunnels a packet over a virtual link using the transit area's
// routing table to reach the far endpoint.
func (s *Simulation) sendVirtual(vname string, src, dst uint32, pkt *ospf.Packet, size int, now int64) {
	r := s.Routers[src]
	var transit uint32
	for _, vi := range s.Topo.Virtual {
		v := &vi
		if v.A == src && v.B == dst || v.B == src && v.A == dst {
			transit = v.Transit
		}
	}
	if transit == 0 {
		s.Metrics.Drop("vl-unknown")
		return
	}
	if !s.virtualPathUp(r, transit, dst) {
		s.Metrics.Drop("vl-unreachable")
		return
	}
	// Deliver after the transit path's current cost/delay has elapsed; we
	// approximate with a fixed hop delay scaled by SPF distance.
	delay := int64(5)
	if res := r.SPFFor(transit); res != nil {
		if d, ok := res.Dist[dst]; ok {
			delay += int64(d)
		}
	}
	s.packetsSent++
	s.Q.Push(now+delay, func() { s.deliver(dst, "vl:"+vname, pkt) })
}

// virtualPathUp reports whether the transit area currently connects the two
// virtual link endpoints.
func (s *Simulation) virtualPathUp(r *ospf.Router, transit, dst uint32) bool {
	res := r.SPFFor(transit)
	if res == nil {
		return false
	}
	_, ok := res.Dist[dst]
	return ok
}

// deliver hands a packet to the destination router.
func (s *Simulation) deliver(dst uint32, linkID string, pkt *ospf.Packet) {
	r := s.Routers[dst]
	if r == nil || s.disabled[dst] {
		return
	}
	s.Metrics.Recv[pkt.Type]++
	r.Receive(linkID, pkt, s.NowTick)
}

// applyWeather updates a link and tells the routers about the change.
func (s *Simulation) applyWeather(e WeatherEvent) {
	ls := s.Links[e.Link]
	if ls == nil {
		return
	}
	wasUp := ls.Up
	oldCost := ls.Cost
	ls.Apply(e, s.NowTick)
	l := s.Topo.Links[e.Link]
	if l == nil {
		return
	}
	switch {
	case wasUp && !ls.Up:
		s.Audit.Event(s.NowTick, ospf.EvWeather, 0, l.Area, "weather %s on %s: link DOWN (%s)", e.Kind, e.Link, e.Reason)
		s.updateCost(l, ls, s.NowTick)
		s.interfaceDown(l.A, l.ID, s.NowTick)
		s.interfaceDown(l.B, l.ID, s.NowTick)
	case !wasUp && ls.Up:
		s.Audit.Event(s.NowTick, ospf.EvWeather, 0, l.Area, "weather %s on %s: link UP, cost %d", e.Kind, e.Link, ls.Cost)
		s.updateCost(l, ls, s.NowTick)
		s.interfaceUp(l.A, l.ID, s.NowTick)
		s.interfaceUp(l.B, l.ID, s.NowTick)
	default:
		if oldCost != ls.Cost {
			s.Audit.Event(s.NowTick, ospf.EvWeather, 0, l.Area, "weather %s on %s: cost %d -> %d", e.Kind, e.Link, oldCost, ls.Cost)
		}
		s.updateCost(l, ls, s.NowTick)
	}
}

func (s *Simulation) updateCost(l *ospf.LinkConfig, ls *LinkState, now int64) {
	for _, id := range []uint32{l.A, l.B} {
		if r := s.Routers[id]; r != nil {
			r.SetInterfaceCost(l.ID, ls.Cost, now)
		}
	}
}

func (s *Simulation) interfaceDown(rid uint32, link string, now int64) {
	if r := s.Routers[rid]; r != nil {
		r.SetInterfaceDown(link, now)
	}
}

func (s *Simulation) interfaceUp(rid uint32, link string, now int64) {
	if r := s.Routers[rid]; r != nil {
		r.SetInterfaceUp(link, now)
	}
}

func (s *Simulation) linkUp(linkID string) bool {
	ls := s.Links[linkID]
	return ls != nil && ls.Up
}

// Batch runs the queue until the next batch boundary (the next weather event
// or an explicit stop time), then lets every router run SPF. It returns the
// number of packets that crossed the wire in the batch.
func (s *Simulation) Batch(until int64) int {
	if s.N <= 3 {
	}
	s.N++
	n := 0
	for {
		at, ok := s.Q.PeekAt()
		if !ok || at > until {
			break
		}
		s.NowTick = at
		ev := s.Q.Pop()
		before := s.packetsSent
		ev.Fn()
		n += s.packetsSent - before
	}
	if s.NowTick < until {
		s.NowTick = until
	}
	// Run SPF to a fixed point. A batch can install advertisements in an
	// order that leaves one area's tree depending on another area's result
	// computed moments earlier; a second pass settles those cross-area
	// dependencies (virtual link costs in particular) so the trees the
	// verifier inspects are internally consistent.
	for _, id := range s.RouterIDs {
		r := s.Routers[id]
		if s.disabled[id] {
			continue
		}
		r.RunSPF(s.NowTick)
		r.RunSPF(s.NowTick)
	}
	return n
}

// Run executes the whole script, batching at each weather event.
func (s *Simulation) Run(duration int64) {
	// The simulation advances in short quanta so that SPF, summary
	// origination and virtual link setup all get a chance to run between
	// packets. Weather events are natural batch boundaries, but a run with no
	// weather still needs regular ticks for convergence to happen at all.
	const quantum = 2_000
	bounds := []int64{}
	for _, e := range s.Weather {
		if e.At < duration {
			bounds = append(bounds, e.At)
		}
	}
	for t := int64(quantum); t < duration; t += quantum {
		bounds = append(bounds, t)
	}
	bounds = append(bounds, duration)
	sort.Slice(bounds, func(i, j int) bool { return bounds[i] < bounds[j] })
	last := int64(0)
	for _, b := range bounds {
		if b <= last {
			continue
		}
		s.Batch(b)
		last = b
	}
	s.Batch(duration)
}

// DisableRouter simulates an administrative shutdown.
func (s *Simulation) DisableRouter(id uint32, at int64) {
	s.disabled[id] = true
	if r := s.Routers[id]; r != nil {
		r.Shutdown(at)
	}
}

// RouterAckStats sums ack bookkeeping across routers.
func (s *Simulation) RouterAckStats() (int, int) {
	a, b := 0, 0
	for _, r := range s.Routers {
		x, y := r.AckStats()
		a += x
		b += y
	}
	return a, b
}

// ApplyCostForTest drives a single link cost change for tests.
func (s *Simulation) ApplyCostForTest(linkID string, cost uint16, now int64) {
	l := s.Topo.Links[linkID]
	ls := s.Links[linkID]
	if l == nil || ls == nil {
		return
	}
	ls.Cost = cost
	s.updateCost(l, ls, now)
}

// Stats returns transport counters.
func (s *Simulation) Stats() (sent, lost, dup int) { return s.packetsSent, s.packetsLost, s.packetsDup }

// QuietRouters returns the set of routers that have had no database install
// and no adjacency change for at least the given quiet period.
func (s *Simulation) QuietRouters(at int64, quiet int64) map[uint32]bool {
	out := map[uint32]bool{}
	for _, id := range s.RouterIDs {
		r := s.Routers[id]
		ok := at-r.LastDBChange() >= quiet
		// A router that has not started talking is not "settled".
		expected := 0
		for _, l := range s.Topo.Links {
			if (l.A == id || l.B == id) && s.Links[l.ID].Up && r.HasInterface(l.ID) {
				expected++
			}
		}
		nbrs := r.Neighbours()
		if ok && len(nbrs) < expected {
			ok = false
		}
		if ok {
			for _, n := range nbrs {
				if at-n.Since < quiet || n.State != "Full" || n.LSRetransmit > 0 || n.LSRequested > 0 {
					ok = false
					break
				}
			}
		}
		if ok {
			out[id] = true
		}
	}
	return out
}

// LinkUpAt reports whether a link is currently usable.
func (s *Simulation) LinkUpAt(linkID string) bool {
	ls := s.Links[linkID]
	return ls != nil && ls.Up
}

// AreaComponents returns the connected components of an area over the links
// that are currently usable, including virtual links that are up. Each
// component is a sorted list of router IDs.
func (s *Simulation) AreaComponents(area uint32) [][]uint32 {
	adj := map[uint32][]uint32{}
	for _, id := range s.RouterIDs {
		if s.Routers[id].AreaEnabled(area) {
			adj[id] = nil
		}
	}
	for _, l := range s.Topo.Links {
		if l.Area != area || !s.Links[l.ID].Up {
			continue
		}
		if _, ok := adj[l.A]; !ok {
			continue
		}
		adj[l.A] = append(adj[l.A], l.B)
		adj[l.B] = append(adj[l.B], l.A)
	}
	if area == 0 {
		// Virtual links join the backbone when their transit area is usable.
		for _, v := range s.Topo.Virtual {
			if !s.virtualLinkUsable(v) {
				continue
			}
			adj[v.A] = append(adj[v.A], v.B)
			adj[v.B] = append(adj[v.B], v.A)
		}
	}
	seen := map[uint32]bool{}
	var comps [][]uint32
	for _, id := range s.RouterIDs {
		if seen[id] {
			continue
		}
		if _, ok := adj[id]; !ok {
			continue
		}
		var comp []uint32
		stack := []uint32{id}
		seen[id] = true
		for len(stack) > 0 {
			cur := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			comp = append(comp, cur)
			for _, nb := range adj[cur] {
				if !seen[nb] {
					seen[nb] = true
					stack = append(stack, nb)
				}
			}
		}
		sort.Slice(comp, func(i, j int) bool { return comp[i] < comp[j] })
		comps = append(comps, comp)
	}
	return comps
}

// virtualLinkUsable reports whether a virtual link's transit area currently
// connects its two endpoints.
func (s *Simulation) virtualLinkUsable(v ospf.VirtualLinkConfig) bool {
	ra := s.Routers[v.A]
	if ra == nil {
		return false
	}
	res := ra.SPFFor(v.Transit)
	if res == nil {
		return false
	}
	_, ok := res.Dist[v.B]
	return ok
}
