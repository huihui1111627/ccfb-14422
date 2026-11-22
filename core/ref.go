package core

import (
	"fmt"
	"strings"
)

// ReferenceRIBs computes the expected routing table of every router directly
// from the global topology (link states, costs, MTUs, areas, virtual links,
// externals) using Dijkstra's algorithm and the OSPF area rules. The
// distributed protocol must converge to exactly these tables.
func (w *World) ReferenceRIBs() map[RouterID]map[Prefix]*Route {
	// 1. per-area adjacency graph (link up + matching MTU => adjacency forms)
	adj := make(map[AreaID]map[RouterID]map[RouterID]int)
	getg := func(a AreaID) map[RouterID]map[RouterID]int {
		if adj[a] == nil {
			adj[a] = make(map[RouterID]map[RouterID]int)
		}
		return adj[a]
	}
	addEdge := func(a AreaID, u, v RouterID, c int) {
		g := getg(a)
		if g[u] == nil {
			g[u] = make(map[RouterID]int)
		}
		if g[v] == nil {
			g[v] = make(map[RouterID]int)
		}
		g[u][v] = c
		g[v][u] = c
	}
	for _, l := range w.Links {
		if !l.Up || l.A.MTU != l.B.MTU {
			continue
		}
		addEdge(l.A.Area, l.A.R.ID, l.B.R.ID, l.Cost)
	}
	// 2. virtual links: up iff endpoints reach each other across the transit area
	for _, vl := range w.VLs {
		g := adj[vl.Transit]
		d := -1
		if g != nil {
			spt := FullSPF(vl.A, g)
			if dd, ok := spt.Dist[vl.B]; ok {
				d = dd
			}
		}
		if d >= 0 {
			addEdge(Backbone, vl.A, vl.B, d)
		}
	}
	// 3. synthesize every router's Router-LSA per area
	routerLSA := make(map[RouterID]map[AreaID]*LSA)
	for _, r := range w.SortedRouters() {
		routerLSA[r.ID] = make(map[AreaID]*LSA)
		for _, area := range r.SortedAreas() {
			body := &RouterLSABody{}
			body.Links = append(body.Links, RouterLink{Type: LinkStub, ID: uint32(r.ID), Data: 0xffffffff, Metric: 0})
			for _, ifc := range r.Ifaces {
				if ifc.Area != area || !ifc.Up() {
					continue
				}
				peer := ifc.Link.Other(ifc)
				if ifc.MTU != peer.MTU {
					continue
				}
				body.Links = append(body.Links, RouterLink{Type: LinkP2P, ID: uint32(peer.R.ID), Metric: ifc.Link.Cost})
			}
			if area == Backbone {
				for _, n := range r.VLNbrs {
					g := adj[n.VL.Transit]
					if g == nil {
						continue
					}
					spt := FullSPF(r.ID, g)
					if d, ok := spt.Dist[n.RtrID]; ok {
						body.Flags |= FlagV
						body.Links = append(body.Links, RouterLink{Type: LinkVirtual, ID: uint32(n.RtrID), Metric: d})
					}
				}
			}
			k := LSAKey{Type: LSARouter, LSID: uint32(r.ID), Adv: r.ID}
			routerLSA[r.ID][area] = &LSA{Key: k, Body: body, InstalledAt: w.Now}
		}
	}
	// 4. per-router per-area SPTs and component membership
	spts := make(map[RouterID]map[AreaID]*SPT)
	comp := make(map[RouterID]map[AreaID]map[RouterID]bool)
	for _, r := range w.SortedRouters() {
		spts[r.ID] = make(map[AreaID]*SPT)
		comp[r.ID] = make(map[AreaID]map[RouterID]bool)
		for _, area := range r.SortedAreas() {
			g := adj[area]
			if g == nil {
				g = map[RouterID]map[RouterID]int{}
			}
			s := FullSPF(r.ID, g)
			spts[r.ID][area] = s
			members := make(map[RouterID]bool)
			for id := range s.Dist {
				members[id] = true
			}
			comp[r.ID][area] = members
		}
	}
	// helper: LSDB view of router r for area A (router LSAs of the component)
	dbsOf := func(r *Router) map[AreaID]map[LSAKey]*LSA {
		dbs := make(map[AreaID]map[LSAKey]*LSA)
		for _, area := range r.SortedAreas() {
			db := make(map[LSAKey]*LSA)
			for id := range comp[r.ID][area] {
				if l := routerLSA[id][area]; l != nil {
					db[l.Key] = l
				}
			}
			dbs[area] = db
		}
		return dbs
	}
	// 5. summary LSAs, generated exactly as ABRs originate them
	type sumKey struct {
		area AreaID
		lsid uint32
		adv  RouterID
	}
	summaryVisible := make(map[RouterID]map[AreaID]map[LSAKey]*LSA)
	for _, r := range w.SortedRouters() {
		summaryVisible[r.ID] = make(map[AreaID]map[LSAKey]*LSA)
		for _, area := range r.SortedAreas() {
			summaryVisible[r.ID][area] = make(map[LSAKey]*LSA)
		}
	}
	addSummary := func(origin *Router, area AreaID, p Prefix, metric int) {
		k := LSAKey{Type: LSASummary, LSID: p.Addr, Adv: origin.ID}
		l := &LSA{Key: k, Body: &SummaryLSABody{Prefix: p, Metric: metric}, InstalledAt: w.Now}
		for _, r := range w.SortedRouters() {
			if comp[r.ID][area][origin.ID] {
				summaryVisible[r.ID][area][k] = l
			}
		}
	}
	isActiveABR := func(r *Router) bool {
		return r.IsABR() && len(spts[r.ID][Backbone].Dist) > 1
	}
	// pass 1: intra routes for every router (no summaries yet)
	intraOf := make(map[RouterID]map[AreaID]map[Prefix]*Route)
	for _, r := range w.SortedRouters() {
		res := computeAll(r, spts[r.ID], dbsOf(r), nil)
		intraOf[r.ID] = res.Intra
	}
	// summaries into the backbone: intra routes of non-backbone areas
	for _, a := range w.SortedRouters() {
		if !isActiveABR(a) {
			continue
		}
		best := make(map[Prefix]int)
		for _, area := range a.SortedAreas() {
			if area == Backbone {
				continue
			}
			for p, rt := range intraOf[a.ID][area] {
				if p == defaultPrefix {
					continue
				}
				if cur, ok := best[p]; !ok || rt.Cost < cur {
					best[p] = rt.Cost
				}
			}
		}
		for p, m := range best {
			addSummary(a, Backbone, p, m)
		}
	}
	// ABR inter-area routes from backbone summaries
	ribOf := func(r *Router, withSummary bool) map[Prefix]*Route {
		dbs := dbsOf(r)
		if withSummary {
			for area := range dbs {
				for k, l := range summaryVisible[r.ID][area] {
					dbs[area][k] = l
				}
			}
		}
		return computeAll(r, spts[r.ID], dbs, nil).RIB
	}
	// summaries into non-backbone areas
	for _, a := range w.SortedRouters() {
		if !isActiveABR(a) {
			continue
		}
		abrRIB := ribOf(a, true) // inter routes learned via backbone summaries
		for _, area := range a.SortedAreas() {
			if area == Backbone {
				continue
			}
			ac := w.Areas[area]
			if ac != nil && ac.TotallyStub {
				addSummary(a, area, defaultPrefix, 1)
				continue
			}
			best := make(map[Prefix]int)
			for _, src := range a.SortedAreas() {
				if src == area {
					continue
				}
				for p, rt := range intraOf[a.ID][src] {
					if p == defaultPrefix {
						continue
					}
					if cur, ok := best[p]; !ok || rt.Cost < cur {
						best[p] = rt.Cost
					}
				}
			}
			for p, rt := range abrRIB {
				if rt.Type != RouteInter || p == defaultPrefix {
					continue
				}
				if _, intra := intraOf[a.ID][area][p]; intra {
					continue
				}
				if cur, ok := best[p]; !ok || rt.Cost < cur {
					best[p] = rt.Cost
				}
			}
			if ac != nil && ac.Stub {
				best[defaultPrefix] = 1
			}
			for p, m := range best {
				addSummary(a, area, p, m)
			}
		}
	}
	// 6. external LSAs: the reference uses each router's actual ExtDB.
	// Flooding-scope correctness (externals never enter stub areas, and
	// reach every router connected through non-stub adjacencies) is checked
	// separately by CheckExternalFlooding.
	// 7. final RIBs
	out := make(map[RouterID]map[Prefix]*Route)
	for _, r := range w.SortedRouters() {
		dbs := dbsOf(r)
		for area := range dbs {
			for k, l := range summaryVisible[r.ID][area] {
				dbs[area][k] = l
			}
		}
		out[r.ID] = computeAll(r, spts[r.ID], dbs, r.ExtDB).RIB
	}
	return out
}

// CheckExternalFlooding verifies external-LSA flooding scope against the
// global topology: routers attached only to stub areas must hold no external
// LSAs, and every router reachable from all ASBRs through non-stub
// adjacencies must hold every external LSA.
func (w *World) CheckExternalFlooding() string {
	var sb strings.Builder
	// adjacency over non-stub areas
	nsAdj := make(map[RouterID]map[RouterID]bool)
	addNS := func(u, v RouterID) {
		if nsAdj[u] == nil {
			nsAdj[u] = make(map[RouterID]bool)
		}
		nsAdj[u][v] = true
	}
	for _, l := range w.Links {
		if !l.Up || l.A.MTU != l.B.MTU {
			continue
		}
		if ac := w.Areas[l.A.Area]; ac != nil && ac.Stub {
			continue
		}
		addNS(l.A.R.ID, l.B.R.ID)
		addNS(l.B.R.ID, l.A.R.ID)
	}
	adj := make(map[AreaID]map[RouterID]map[RouterID]int)
	for _, l := range w.Links {
		if !l.Up || l.A.MTU != l.B.MTU {
			continue
		}
		if adj[l.A.Area] == nil {
			adj[l.A.Area] = make(map[RouterID]map[RouterID]int)
		}
		a, b := l.A.R.ID, l.B.R.ID
		if adj[l.A.Area][a] == nil {
			adj[l.A.Area][a] = make(map[RouterID]int)
		}
		if adj[l.A.Area][b] == nil {
			adj[l.A.Area][b] = make(map[RouterID]int)
		}
		adj[l.A.Area][a][b] = l.Cost
		adj[l.A.Area][b][a] = l.Cost
	}
	for _, vl := range w.VLs {
		g := adj[vl.Transit]
		if g == nil {
			continue
		}
		spt := FullSPF(vl.A, g)
		if _, ok := spt.Dist[vl.B]; ok {
			addNS(vl.A, vl.B)
			addNS(vl.B, vl.A)
		}
	}
	// per-ASBR BFS: an external LSA reaches exactly the routers reachable
	// from its originator over non-stub adjacencies
	want := make(map[RouterID]map[LSAKey]bool)
	for _, r := range w.SortedRouters() {
		if !r.ASBR {
			continue
		}
		seen := map[RouterID]bool{r.ID: true}
		queue := []RouterID{r.ID}
		for len(queue) > 0 {
			u := queue[0]
			queue = queue[1:]
			for v := range nsAdj[u] {
				if !seen[v] {
					seen[v] = true
					queue = append(queue, v)
				}
			}
		}
		for id := range seen {
			if want[id] == nil {
				want[id] = make(map[LSAKey]bool)
			}
			for _, st := range r.Statics {
				want[id][LSAKey{Type: LSAExternal, LSID: st.Prefix.Addr, Adv: r.ID}] = true
			}
		}
	}
	for _, r := range w.SortedRouters() {
		stubOnly := true
		for area := range r.AreaSet {
			if ac := w.Areas[area]; ac == nil || !ac.Stub {
				stubOnly = false
			}
		}
		if stubOnly && len(r.ExtDB) != 0 {
			fmt.Fprintf(&sb, "r=%s stub-only but holds %d external LSAs\n", IDStr(r.ID), len(r.ExtDB))
		}
		for k := range want[r.ID] {
			if r.ExtDB[k] == nil {
				fmt.Fprintf(&sb, "r=%s missing external LSA %s\n", IDStr(r.ID), k)
			}
		}
	}
	return sb.String()
}
