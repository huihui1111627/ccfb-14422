package core

import "sort"

// VLink is a configured virtual link between two ABRs across a transit area.
type VLink struct {
	ID      int
	A, B    RouterID
	Transit AreaID
}

// Other returns the peer endpoint id.
func (vl *VLink) Other(id RouterID) RouterID {
	if id == vl.A {
		return vl.B
	}
	return vl.A
}

// AddVLink configures a virtual link between routers a and b.
func (w *World) AddVLink(a, b *Router, transit AreaID) *VLink {
	if a == b {
		panic("virtual link endpoints must differ")
	}
	vl := &VLink{ID: len(w.VLs), A: a.ID, B: b.ID, Transit: transit}
	w.VLs = append(w.VLs, vl)
	for _, ep := range []*Router{a, b} {
		peer := vl.Other(ep.ID)
		n := &Neighbor{
			RtrID:    peer,
			VL:       vl,
			R:        ep,
			State:    NbrDown,
			RetxList: make(map[LSAKey]*LSA),
		}
		ep.VLNbrs = append(ep.VLNbrs, n)
		ep.AreaSet[Backbone] = true
		if ep.LSDB[Backbone] == nil {
			ep.LSDB[Backbone] = make(map[LSAKey]*LSA)
		}
		if w.Areas[Backbone] == nil {
			w.Areas[Backbone] = &AreaConf{}
		}
	}
	return vl
}

func (r *Router) vlNeighbor(vl *VLink) *Neighbor {
	for _, n := range r.VLNbrs {
		if n.VL == vl {
			return n
		}
	}
	return nil
}

// backboneAttached reports whether the router has usable backbone connectivity.
func (r *Router) backboneAttached() bool {
	s := r.SPTs[Backbone]
	return s != nil && len(s.Dist) > 1
}

// --- summary LSA origination (ABR) -----------------------------------------

var defaultPrefix = Prefix{Addr: 0, Len: 0}

func (r *Router) updateSummaries() {
	if !r.IsABR() || !r.backboneAttached() {
		r.withdrawAllSummaries()
		return
	}
	want := make(map[AreaID]map[Prefix]int)
	for _, area := range r.SortedAreas() {
		want[area] = make(map[Prefix]int)
		ac := r.W.Areas[area]
		if area != Backbone && ac != nil && ac.TotallyStub {
			// totally stubby: only a default route is injected
			want[area][defaultPrefix] = 1
			continue
		}
		// intra-area routes of all other attached areas
		for _, src := range r.SortedAreas() {
			if src == area {
				continue
			}
			for _, p := range sortedPrefixes(r.IntraRoutes[src]) {
				rt := r.IntraRoutes[src][p]
				if p == defaultPrefix {
					continue
				}
				if cur, ok := want[area][p]; !ok || rt.Cost < cur {
					want[area][p] = rt.Cost
				}
			}
		}
		if area != Backbone {
			// inter-area routes learned via the backbone
			for _, p := range sortedPrefixes(r.RIB) {
				rt := r.RIB[p]
				if rt.Type != RouteInter || p == defaultPrefix {
					continue
				}
				if _, intra := r.IntraRoutes[area][p]; intra {
					continue
				}
				if cur, ok := want[area][p]; !ok || rt.Cost < cur {
					want[area][p] = rt.Cost
				}
			}
			if ac != nil && ac.Stub {
				want[area][defaultPrefix] = 1
			}
		}
	}
	// originate / update
	for _, area := range r.SortedAreas() {
		for _, p := range sortedPrefixes2(want[area]) {
			r.ensureSummary(area, p, want[area][p])
		}
	}
	// withdraw stale summaries
	for _, area := range r.SortedAreas() {
		m := r.areaSummaries[area]
		for _, p := range sortedPrefixKeys(m) {
			if _, ok := want[area][p]; !ok {
				k := m[p].Key
				delete(m, p)
				r.flushLSA(area, k)
			}
		}
	}
}

func sortedPrefixes2(m map[Prefix]int) []Prefix {
	ps := make([]Prefix, 0, len(m))
	for p := range m {
		ps = append(ps, p)
	}
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Addr != ps[j].Addr {
			return ps[i].Addr < ps[j].Addr
		}
		return ps[i].Len < ps[j].Len
	})
	return ps
}

func sortedPrefixKeys(m map[Prefix]*LSA) []Prefix {
	ps := make([]Prefix, 0, len(m))
	for p := range m {
		ps = append(ps, p)
	}
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Addr != ps[j].Addr {
			return ps[i].Addr < ps[j].Addr
		}
		return ps[i].Len < ps[j].Len
	})
	return ps
}

func (r *Router) ensureSummary(area AreaID, p Prefix, metric int) {
	if r.areaSummaries[area] == nil {
		r.areaSummaries[area] = make(map[Prefix]*LSA)
	}
	if old := r.areaSummaries[area][p]; old != nil {
		if old.SummaryBody().Metric == metric {
			return // unchanged
		}
	}
	k := LSAKey{Type: LSASummary, LSID: p.Addr, Adv: r.ID}
	r.originate(area, k, &SummaryLSABody{Prefix: p, Metric: metric})
	r.areaSummaries[area][p] = r.Self[sk(area, k)]
}

func (r *Router) withdrawAllSummaries() {
	for _, area := range r.SortedAreas() {
		m := r.areaSummaries[area]
		for _, p := range sortedPrefixKeys(m) {
			k := m[p].Key
			r.flushLSA(area, k)
		}
		r.areaSummaries[area] = make(map[Prefix]*LSA)
	}
}

// --- virtual links -----------------------------------------------------------

// updateVLinks brings virtual links up or down based on intra-area reachability
// across the transit area.
func (r *Router) updateVLinks() {
	for _, n := range r.VLNbrs {
		vl := n.VL
		var rt *Route
		if m := r.IntraRoutes[vl.Transit]; m != nil {
			rt = m[Prefix{Addr: uint32(n.RtrID), Len: 32}]
		}
		if rt != nil {
			if !n.VLUp || n.VLCost != rt.Cost {
				n.VLUp = true
				n.VLCost = rt.Cost
				r.W.MarkChange()
				r.startVLHello(n)
				r.originateRouterLSA(Backbone)
			}
		} else if n.VLUp {
			n.VLUp = false
			r.stopVLHello(n)
			r.killNeighbor(n)
		}
	}
}

func (r *Router) startVLHello(n *Neighbor) {
	if n.helloTimer != nil {
		return
	}
	w := r.W
	var fn func()
	fn = func() {
		if !n.VLUp {
			n.helloTimer = nil
			return
		}
		pkt := &Packet{Type: PktHello}
		if n.State >= NbrInit {
			pkt.Seen = []RouterID{n.RtrID}
		}
		n.sendP(pkt, true)
		n.helloTimer = w.Schedule(w.Cfg.HelloInterval, true, "vl-hello", fn)
	}
	n.helloTimer = w.Schedule(1, true, "vl-hello", fn)
}

func (r *Router) stopVLHello(n *Neighbor) {
	if n.helloTimer != nil {
		n.helloTimer.Cancel()
		n.helloTimer = nil
	}
}

func (r *Router) handlePacketVL(vl *VLink, pkt *Packet) {
	n := r.vlNeighbor(vl)
	if n == nil || !n.VLUp {
		return
	}
	switch pkt.Type {
	case PktHello:
		r.handleVLHello(n, pkt)
	case PktDD:
		r.handleDD(n, pkt)
	case PktLSR:
		r.handleLSR(n, pkt)
	case PktLSU:
		r.handleLSU(n, pkt)
	case PktLSAck:
		r.handleLSAck(n, pkt)
	}
}

func (r *Router) handleVLHello(n *Neighbor, pkt *Packet) {
	w := r.W
	if n.State == NbrDown {
		n.State = NbrInit
		w.MarkChange()
	}
	if n.deadTimer != nil {
		n.deadTimer.Cancel()
	}
	n.deadTimer = w.Schedule(w.Cfg.DeadInterval, true, "vl-dead", func() {
		r.killNeighbor(n)
	})
	seenMe := false
	for _, id := range pkt.Seen {
		if id == r.ID {
			seenMe = true
		}
	}
	if seenMe && n.State < NbrTwoWay {
		n.State = NbrTwoWay
		w.MarkChange()
		r.nbrExStart(n)
	}
}

// --- external routes -----------------------------------------------------------

// originateExternals originates AS-external LSAs for configured statics.
func (r *Router) originateExternals() {
	if !r.ASBR {
		return
	}
	for i := range r.Statics {
		st := r.Statics[i]
		k := LSAKey{Type: LSAExternal, LSID: st.Prefix.Addr, Adv: r.ID}
		body := &ExternalLSABody{Prefix: st.Prefix, Metric: st.Metric}
		r.originate(Backbone, k, body)
	}
}

// --- boot ----------------------------------------------------------------------

// Boot starts all routing processes: originates initial LSAs and brings
// interfaces up.
func (w *World) Boot() {
	for _, r := range w.SortedRouters() {
		for _, area := range r.SortedAreas() {
			r.originateRouterLSA(area)
		}
		r.originateExternals()
	}
	for _, l := range w.Links {
		if l.Up {
			l.A.R.ifaceUp(l.A)
			l.B.R.ifaceUp(l.B)
		}
	}
}
