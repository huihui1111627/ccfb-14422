package ospf

import (
	"sort"
)

// ---- ABR determination ----------------------------------------------------

// IsABR reports whether the router has interfaces in more than one area, or
// terminates a virtual link in the backbone (requirement 6).
func (r *Router) IsABR() bool {
	n := 0
	for _, a := range r.Areas {
		if a >= 0 {
			n++
		}
	}
	if n > 1 {
		return true
	}
	return len(r.VirInterfaces) > 0
}

// ---- Summary origination --------------------------------------------------

// orchestrateAggregates recomputes and (re)originates every summary LSA this
// ABR should own, based on the current per-area SPF results.
//
// For every area A that the ABR serves other than the backbone, it injects
// into A:
//   - a type 3 for each intra-area prefix of the backbone (unless the target
//     area is totally stubby, where only a default summary is sent),
//   - a type 3 for each ASBR's summaries,
//   - a type 4 for each ASBR when routing external traffic.
func (r *Router) orchestrateAggregates(now int64) {
	if !r.IsABR() {
		return
	}
	// Summaries are injected into every area the ABR serves, the backbone
	// included: the backbone needs type 3s describing non-backbone prefixes
	// so that an ASBR or another ABR can reach them (requirement 6). The
	// backbone is never stubby, so summariesFor returns the normal set there.
	for _, area := range r.Areas {
		want := r.summariesFor(area)
		r.syncSummaries(area, want, now)
	}
}

// summaryWant describes a desired summary advertisement.
type summaryWant struct {
	key  LSAKey
	l    *LSA
	area uint32
}

// summariesFor builds the summary advertisements an ABR owes to one area.
func (r *Router) summariesFor(area uint32) []summaryWant {
	totallyStub := r.Topo.Areas[area] != nil && r.Topo.Areas[area].Type == TotallyStubArea
	stub := r.isStubArea(area)
	var out []summaryWant
	// Default summary into a stub area (requirement 8).
	if stub {
		p := Prefix{Network: 0, Mask: 0, Metric: 1}
		l := BuildSummaryLSA(LSASummary, 0, r.ID, r.peekSeq(area, LSAKey{LSASummary, 0, r.ID}), r.areaOptions(area), p)
		out = append(out, summaryWant{key: l.Key(), l: l, area: area})
	}
	if totallyStub {
		// Only the default route is injected into a totally stubby area.
		return out
	}
	// Aggregated ranges configured for the source areas take precedence.
	aggCovered := map[[2]uint32]bool{}
	for _, ag := range r.aggregates() {
		aggCovered[[2]uint32{ag.Network & ag.Mask, ag.Mask}] = true
	}
	// Inter-area reachability: advertise each other area's intra-area
	// prefixes into this area. For the backbone that means the non-backbone
	// prefixes; for a non-backbone area it means the backbone's prefixes plus
	// the other non-backbone areas' prefixes (which route through the
	// backbone).
	for _, src := range r.Areas {
		if src == area {
			continue
		}
		for _, rt := range r.summarySourceRoutes(src) {
			if r.coveredByAggregate(rt, out) {
				continue
			}
			p := Prefix{Network: rt.Prefix & rt.Mask, Mask: rt.Mask, Metric: rt.Cost}
			if p.Metric > LSInfinity {
				p.Metric = LSInfinity
			}
			k := LSAKey{LSASummary, p.Network, r.ID}
			l := BuildSummaryLSA(LSASummary, p.Network, r.ID, r.peekSeq(area, k), r.areaOptions(area), p)
			out = append(out, summaryWant{key: k, l: l, area: area})
		}
	}
	// ASBR summaries (type 4) when the area carries external routing. A
	// type 4 is only injected into areas *other* than the one the ASBR lives
	// in; routers there already see the ASBR's own router LSA.
	if !stub {
		for _, asbr := range r.asbrsOutside(area) {
			if asbr == r.ID {
				continue
			}
			p := Prefix{Network: asbr, Mask: 0xffffffff, Metric: r.costToRouter(asbr)}
			k := LSAKey{LSASummaryAS, asbr, r.ID}
			l := BuildSummaryLSA(LSASummaryAS, asbr, r.ID, r.peekSeq(area, k), r.areaOptions(area), p)
			out = append(out, summaryWant{key: k, l: l, area: area})
		}
	}
	sort.Slice(out, func(i, j int) bool { return keyLess(out[i].key, out[j].key) })
	return out
}

// aggregates returns the configured aggregate ranges.
func (r *Router) aggregates() []Aggregate {
	var out []Aggregate
	for _, a := range r.Topo.Areas {
		if a == nil {
			continue
		}
		out = append(out, a.Aggregates...)
	}
	return out
}

// summarySourceRoutes lists the intra-area routes of one area that may be
// summarised into another area.
func (r *Router) summarySourceRoutes(area uint32) []*Route {
	res := r.spfArea[area]
	if res == nil {
		return nil
	}
	// Only intra-area routes are sources for summaries. Including derived
	// inter-area routes would feed summaries back into the computation and
	// make the advertisement set oscillate.
	out := make([]*Route, 0, len(res.Routes))
	out = append(out, res.Routes...)
	return out
}

// coveredByAggregate supposes a route is subsumed by a configured aggregate.
func (r *Router) coveredByAggregate(rt *Route, _ []summaryWant) bool {
	for _, ag := range r.aggregates() {
		if rt.Prefix&ag.Mask == ag.Network&ag.Mask && maskBits(rt.Mask) >= maskBits(ag.Mask) {
			return true
		}
	}
	return false
}

// asbrsOutside lists ASBRs reachable through some other area of this ABR; these
// are the ones that need a type 4 summary in the given area.
func (r *Router) asbrsOutside(area uint32) []uint32 {
	set := map[uint32]bool{}
	for _, other := range r.Areas {
		if other == area {
			continue
		}
		for _, asbr := range r.knownASBRs(other) {
			set[asbr] = true
		}
	}
	out := make([]uint32, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// knownASBRs lists the ASBRs reachable within an area (from type 1 flags).
func (r *Router) knownASBRs(area uint32) []uint32 {
	var out []uint32
	for k, l := range r.areaDB[area] {
		if k.Type != LSARouter || l.Age >= MaxAge {
			continue
		}
		if l.Flags&FlagASBR != 0 {
			out = append(out, l.AdvRtr)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// costToRouter returns our SPF distance to a router in the most relevant
// area, or LSInfinity when unreachable.
func (r *Router) costToRouter(id uint32) uint32 {
	best := uint32(LSInfinity)
	for _, area := range r.Areas {
		if res := r.spfArea[area]; res != nil {
			if d, ok := res.Dist[id]; ok && d < best {
				best = d
			}
		}
	}
	return best
}

// peekSeq returns the sequence that will be used for a new instance without
// consuming it.
func (r *Router) peekSeq(area uint32, k LSAKey) uint32 {
	s := r.seqsFor(area)[k]
	if s == 0 {
		return InitialSeqNum
	}
	return s + 1
}

// syncSummaries installs, updates and withdraws summary advertisements so the
// area database matches want. An unchanged summary is left alone: the refresh
// timer is what ages and re-floods self-originated advertisements, and
// re-originating on every SPF run would flood the area continuously.
func (r *Router) syncSummaries(area uint32, want []summaryWant, now int64) {
	wantKeys := map[LSAKey]*LSA{}
	for _, w := range want {
		wantKeys[w.key] = w.l
	}
	for _, w := range want {
		cur := r.selfFor(area)[w.key]
		l := w.l
		if cur != nil && cur.SameContent(l) {
			continue
		}
		l.Seq = r.bumpSeq(area, w.key)
		l.FillDerived() // the checksum covers the sequence number
		l.ReceivedAt = now
		l.SourceRtr = r.ID
		old := r.areaDB[area][w.key]
		r.selfFor(area)[w.key] = l
		r.db(area)[w.key] = l
		r.Metrics.Originated(l)
		r.noteChange(area, w.key, old, l)
		r.flood(area, l, now)
	}
	// Withdraw summaries that are no longer applicable.
	var del []LSAKey
	for k, l := range r.areaDB[area] {
		if (k.Type == LSASummary || k.Type == LSASummaryAS) && k.AdvRtr == r.ID {
			if _, keep := wantKeys[k]; !keep {
				_ = l
				del = append(del, k)
			}
		}
	}
	sortKeys(del)
	for _, k := range del {
		r.flushLSA(area, k, now)
		delete(r.selfFor(area), k)
	}
}

// SameContent compares two advertisements ignoring sequence, checksum and
// age. Used to decide whether a summary needs re-origination.
func (l *LSA) SameContent(o *LSA) bool {
	return l.Type == o.Type && l.ID == o.ID && l.AdvRtr == o.AdvRtr &&
		l.Options == o.Options && l.Addr == o.Addr && l.Flags == o.Flags &&
		l.Count == o.Count && string(l.Body) == string(o.Body)
}

// ---- Inter-area and external route computation ---------------------------

// interAreaRoutes derives type 3/4 based routes from the LSDB.
func (r *Router) interAreaRoutes() []*Route {
	var out []*Route
	for _, area := range r.Areas {
		res := r.spfArea[area]
		if res == nil {
			continue
		}
		for k, l := range r.areaDB[area] {
			if k.Type != LSASummary || l.Age >= MaxAge || l.AdvRtr == r.ID {
				continue
			}
			// The advertising ABR must be reachable intra-area.
			abrd, ok := res.Dist[l.AdvRtr]
			if !ok {
				continue
			}
			ps := DecodePrefixes(LSASummary, l.Body)
			for _, p := range ps {
				rt := &Route{
					Prefix:  p.Network & p.Mask,
					Mask:    p.Mask,
					Cost:    abrd + p.Metric,
					NextHop: res.NextHop[l.AdvRtr],
					Area:    area,
					Type:    RouteInter,
					Origin:  l.AdvRtr,
					Path:    res.pathTo(l.AdvRtr),
				}
				rt.ViaBackbone = area == 0
				out = append(out, rt)
			}
		}
	}
	return out
}

// externalRoutes derives type 5 based routes.
func (r *Router) externalRoutes() []*Route {
	var out []*Route
	for _, area := range r.Areas {
		if r.isStubArea(area) {
			continue
		}
		res := r.spfArea[area]
		if res == nil {
			continue
		}
		for k, l := range r.areaDB[area] {
			if k.Type != LSAASExternal || l.Age >= MaxAge {
				continue
			}
			asbrCost, ok := res.Dist[l.AdvRtr]
			if !ok {
				// The ASBR may be reachable through a type 4 summary.
				asbrCost = r.summaryCostToASBR(area, l.AdvRtr)
				if asbrCost == LSInfinity {
					continue
				}
			}
			nextHop := res.NextHop[l.AdvRtr]
			if nextHop == 0 {
				nextHop = l.AdvRtr
			}
			for _, p := range DecodePrefixes(LSAASExternal, l.Body) {
				out = append(out, &Route{
					Prefix:  p.Network & p.Mask,
					Mask:    p.Mask,
					Cost:    asbrCost + p.Metric,
					NextHop: nextHop,
					Area:    area,
					Type:    RouteExternal,
					Origin:  l.AdvRtr,
					Path:    res.pathTo(l.AdvRtr),
				})
			}
		}
	}
	return out
}

// summaryCostToASBR resolves an ASBR cost via type 4 advertisements.
func (r *Router) summaryCostToASBR(area uint32, asbr uint32) uint32 {
	res := r.spfArea[area]
	if res == nil {
		return LSInfinity
	}
	best := uint32(LSInfinity)
	for k, l := range r.areaDB[area] {
		if k.Type != LSASummaryAS || l.Age >= MaxAge || k.ID != asbr {
			continue
		}
		abrd, ok := res.Dist[l.AdvRtr]
		if !ok {
			continue
		}
		for _, p := range DecodePrefixes(LSASummaryAS, l.Body) {
			if c := abrd + p.Metric; c < best {
				best = c
			}
		}
	}
	return best
}

// ---- Virtual links --------------------------------------------------------

// TransitCost returns the intra-area cost of the virtual link through its
// transit area, as computed by the backbone-side SPF over the transit graph.
func (r *Router) TransitCost(v *VirtualLinkConfig) (uint16, bool) {
	res := r.spfArea[v.Transit]
	if res == nil {
		return 0, false
	}
	// The cost of the virtual link is the distance to the *far* endpoint
	// through the transit area. Which endpoint is far depends on which router
	// is asking.
	far := v.A
	if r.ID == v.A {
		far = v.B
	}
	d, ok := res.Dist[far]
	if !ok {
		return 0, false
	}
	if d == 0 {
		// A zero distance means the far endpoint is this router, which cannot
		// happen for a real virtual link; treat it as unusable.
		return 0, false
	}
	if d > 65535 {
		return 65535, true
	}
	return uint16(d), true
}

// virtualUsable reports whether the transit area currently provides a path.
func (r *Router) virtualUsable(transit uint32) bool {
	res := r.spfArea[transit]
	if res == nil {
		return false
	}
	for vi := range r.Topo.Virtual {
		v := &r.Topo.Virtual[vi]
		if v.Transit != transit {
			continue
		}
		if v.A == r.ID {
			if _, ok := res.Dist[v.B]; ok {
				return true
			}
		} else if v.B == r.ID {
			if _, ok := res.Dist[v.A]; ok {
				return true
			}
		}
	}
	return false
}

// virtualCost is the cost advertised on the virtual link.
func (r *Router) virtualCost(transit uint32) uint16 {
	if c, ok := r.TransitCostForArea(transit); ok {
		return c
	}
	return 65535
}

// TransitCostForArea returns the cost to the far end of any virtual link in
// the transit area.
func (r *Router) TransitCostForArea(transit uint32) (uint16, bool) {
	res := r.spfArea[transit]
	if res == nil {
		return 0, false
	}
	best := uint32(LSInfinity)
	for vi := range r.Topo.Virtual {
		v := &r.Topo.Virtual[vi]
		if v.Transit != transit {
			continue
		}
		if v.A != r.ID && v.B != r.ID {
			continue
		}
		other := v.A
		if other == r.ID {
			other = v.B
		}
		if d, ok := res.Dist[other]; ok && d < best {
			best = d
		}
	}
	if best == LSInfinity {
		return 0, false
	}
	if best > 65535 {
		best = 65535
	}
	return uint16(best), true
}

// virtualInterfaceAddr is the local address used for the virtual link.
func (r *Router) virtualInterfaceAddr(peer uint32) uint32 {
	lo := r.ID
	if peer < lo {
		lo = peer
	}
	return 0x0b000000 | (lo & 0xffffff)
}
