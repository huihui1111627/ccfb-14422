package core

import (
	"container/heap"
	"fmt"
	"sort"
)

// SPT is a shortest-path tree rooted at one router.
type SPT struct {
	Root     RouterID
	Dist     map[RouterID]int
	Parent   map[RouterID]RouterID
	NextHops map[RouterID][]RouterID // sorted first-hop neighbors
}

type spfItem struct {
	id RouterID
	d  int
}
type spfHeap []spfItem

func (h spfHeap) Len() int { return len(h) }
func (h spfHeap) Less(i, j int) bool {
	if h[i].d != h[j].d {
		return h[i].d < h[j].d
	}
	return h[i].id < h[j].id
}
func (h spfHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *spfHeap) Push(x interface{}) { *h = append(*h, x.(spfItem)) }
func (h *spfHeap) Pop() interface{} {
	old := *h
	n := len(old)
	it := old[n-1]
	*h = old[:n-1]
	return it
}

// buildAreaGraph builds the directed graph for an area from its Router-LSAs.
// An edge exists only when both endpoints advertise each other (RFC 2328
// bidirectional connectivity check). MaxAge tombstones do not participate.
func buildAreaGraph(db map[LSAKey]*LSA, now, maxAge int64) map[RouterID]map[RouterID]int {
	links := make(map[RouterID][]RouterLink)
	for _, k := range sortedKeys(db) {
		l := db[k]
		if l.Key.Type == LSARouter && l.Age(now) < maxAge {
			links[l.Key.Adv] = l.RouterBody().Links
		}
	}
	has := func(from, to RouterID) bool {
		for _, lk := range links[from] {
			if (lk.Type == LinkP2P || lk.Type == LinkVirtual) && RouterID(lk.ID) == to {
				return true
			}
		}
		return false
	}
	adj := make(map[RouterID]map[RouterID]int)
	for id := range links {
		adj[id] = make(map[RouterID]int)
	}
	for from, ls := range links {
		for _, lk := range ls {
			if lk.Type != LinkP2P && lk.Type != LinkVirtual {
				continue
			}
			to := RouterID(lk.ID)
			if has(to, from) {
				adj[from][to] = lk.Metric
			}
		}
	}
	return adj
}

func sortedAdj(adj map[RouterID]map[RouterID]int, u RouterID) []RouterID {
	vs := make([]RouterID, 0, len(adj[u]))
	for v := range adj[u] {
		vs = append(vs, v)
	}
	sort.Slice(vs, func(i, j int) bool { return vs[i] < vs[j] })
	return vs
}

func nhOf(spt *SPT, u, v RouterID) []RouterID {
	if u == spt.Root {
		return []RouterID{v}
	}
	return spt.NextHops[u]
}

// FullSPF runs Dijkstra from root over the area graph.
func FullSPF(root RouterID, adj map[RouterID]map[RouterID]int) *SPT {
	spt := &SPT{
		Root:     root,
		Dist:     map[RouterID]int{root: 0},
		Parent:   make(map[RouterID]RouterID),
		NextHops: make(map[RouterID][]RouterID),
	}
	h := &spfHeap{{root, 0}}
	done := make(map[RouterID]bool)
	for h.Len() > 0 {
		it := heap.Pop(h).(spfItem)
		u := it.id
		if done[u] {
			continue
		}
		done[u] = true
		for _, v := range sortedAdj(adj, u) {
			if done[v] {
				continue
			}
			nd := spt.Dist[u] + adj[u][v]
			dv, ok := spt.Dist[v]
			if !ok || nd < dv {
				spt.Dist[v] = nd
				spt.Parent[v] = u
				spt.NextHops[v] = append([]RouterID(nil), nhOf(spt, u, v)...)
				heap.Push(h, spfItem{v, nd})
			} else if nd == dv {
				spt.NextHops[v] = unionNH(spt.NextHops[v], nhOf(spt, u, v))
			}
		}
	}
	return spt
}

func unionNH(a, b []RouterID) []RouterID {
	set := make(map[RouterID]bool)
	for _, x := range a {
		set[x] = true
	}
	for _, x := range b {
		set[x] = true
	}
	out := make([]RouterID, 0, len(set))
	for x := range set {
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// iSPF incrementally updates the SPT for single-link changes instead of
// recomputing the whole tree (Narvaez-style incremental SPF). The change list
// is derived from Router-LSA diffs and may be asymmetric (only one direction
// of a link reported so far); the current graph is the source of truth for
// edge existence and cost.
func iSPF(spt *SPT, adj map[RouterID]map[RouterID]int, changes []LinkChange) {
	detached := make(map[RouterID]bool)
	var improved []RouterID
	tryDetach := func(u, v RouterID) {
		// does the tree path to v use edge u->v, and did that edge worsen?
		if p, ok := spt.Parent[v]; !ok || p != u {
			return
		}
		cOld := spt.Dist[v] - spt.Dist[u]
		cNew, ok := adj[u][v]
		if !ok || cNew > cOld {
			markSubtree(spt, v, detached)
		}
	}
	tryRelax := func(u, v RouterID) {
		c, ok := adj[u][v]
		if !ok {
			return
		}
		du, ok := spt.Dist[u]
		if !ok {
			return
		}
		if dv, ok := spt.Dist[v]; !ok || du+c < dv {
			spt.Dist[v] = du + c
			spt.Parent[v] = u
			improved = append(improved, v)
		}
	}
	for _, ch := range changes {
		tryDetach(ch.From, ch.To)
		tryDetach(ch.To, ch.From)
	}
	if len(detached) > 0 {
		for id := range detached {
			delete(spt.Dist, id)
			delete(spt.Parent, id)
			delete(spt.NextHops, id)
		}
		reattach(spt, adj, detached)
	}
	for _, ch := range changes {
		tryRelax(ch.From, ch.To)
		tryRelax(ch.To, ch.From)
	}
	for _, v := range improved {
		improveFrom(spt, adj, v)
	}
	recomputeNextHops(spt, adj)
}

func markSubtree(spt *SPT, root RouterID, out map[RouterID]bool) {
	children := make(map[RouterID][]RouterID)
	for v, p := range spt.Parent {
		children[p] = append(children[p], v)
	}
	stack := []RouterID{root}
	for len(stack) > 0 {
		v := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		out[v] = true
		stack = append(stack, children[v]...)
	}
}

// reattach runs Dijkstra from the surviving tree to re-attach detached nodes.
func reattach(spt *SPT, adj map[RouterID]map[RouterID]int, detached map[RouterID]bool) {
	h := &spfHeap{}
	for id, d := range spt.Dist {
		for v := range adj[id] {
			if detached[v] {
				heap.Push(h, spfItem{id, d})
				break
			}
		}
	}
	done := make(map[RouterID]bool)
	for h.Len() > 0 {
		it := heap.Pop(h).(spfItem)
		u := it.id
		if done[u] {
			continue
		}
		done[u] = true
		if it.d > spt.Dist[u] {
			continue
		}
		for _, v := range sortedAdj(adj, u) {
			if done[v] {
				continue
			}
			nd := spt.Dist[u] + adj[u][v]
			if dv, ok := spt.Dist[v]; !ok || nd < dv {
				spt.Dist[v] = nd
				spt.Parent[v] = u
				heap.Push(h, spfItem{v, nd})
			}
		}
	}
}

// improveFrom propagates strictly-better distances from a node.
func improveFrom(spt *SPT, adj map[RouterID]map[RouterID]int, src RouterID) {
	h := &spfHeap{{src, spt.Dist[src]}}
	done := make(map[RouterID]bool)
	for h.Len() > 0 {
		it := heap.Pop(h).(spfItem)
		u := it.id
		if done[u] {
			continue
		}
		done[u] = true
		if it.d > spt.Dist[u] {
			continue
		}
		for _, v := range sortedAdj(adj, u) {
			if done[v] {
				continue
			}
			nd := spt.Dist[u] + adj[u][v]
			if dv, ok := spt.Dist[v]; !ok || nd < dv {
				spt.Dist[v] = nd
				spt.Parent[v] = u
				heap.Push(h, spfItem{v, nd})
			}
		}
	}
}

// recomputeNextHops derives ECMP first hops from the equal-cost DAG in one
// linear pass ordered by distance (the distances themselves were computed
// incrementally; this pass only re-derives next-hop sets).
func recomputeNextHops(spt *SPT, adj map[RouterID]map[RouterID]int) {
	nodes := make([]RouterID, 0, len(spt.Dist))
	for id := range spt.Dist {
		nodes = append(nodes, id)
	}
	sort.Slice(nodes, func(i, j int) bool {
		a, b := nodes[i], nodes[j]
		if spt.Dist[a] != spt.Dist[b] {
			return spt.Dist[a] < spt.Dist[b]
		}
		return a < b
	})
	spt.NextHops = make(map[RouterID][]RouterID)
	for _, v := range nodes {
		if v == spt.Root {
			continue
		}
		var nh []RouterID
		for _, u := range sortedAdj(adj, v) {
			// edge existence is symmetric, cost need not be: the path to v
			// uses the incoming edge cost adj[u][v]
			c, ok := adj[u][v]
			if !ok {
				continue
			}
			du, ok := spt.Dist[u]
			if ok && du+c == spt.Dist[v] {
				nh = unionNH(nh, nhOf(spt, u, v))
			}
		}
		spt.NextHops[v] = nh
	}
}

func sptEqual(a, b *SPT) bool {
	if len(a.Dist) != len(b.Dist) {
		return false
	}
	for id, d := range a.Dist {
		if bd, ok := b.Dist[id]; !ok || bd != d {
			return false
		}
		an := a.NextHops[id]
		bn := b.NextHops[id]
		if len(an) != len(bn) {
			return false
		}
		for i := range an {
			if an[i] != bn[i] {
				return false
			}
		}
	}
	return true
}

// --- route computation ----------------------------------------------------

// RouteResult holds the computed routing state of one router.
type RouteResult struct {
	Intra map[AreaID]map[Prefix]*Route
	RIB   map[Prefix]*Route
}

func maskLen(mask uint32) uint8 {
	n := uint8(0)
	for i := 31; i >= 0; i-- {
		if mask>>uint(i)&1 == 1 {
			n++
		}
	}
	return n
}

func addRoute(m map[Prefix]*Route, cand *Route) {
	cur := m[cand.Prefix]
	if cur == nil || routeBetter(cand, cur) {
		cp := *cand
		m[cand.Prefix] = &cp
	} else if routeEqualPref(cur, cand) {
		cur.NextHops = unionNH(cur.NextHops, cand.NextHops)
	}
}

func routeBetter(a, b *Route) bool {
	if a.Type != b.Type {
		return a.Type < b.Type
	}
	if a.Cost != b.Cost {
		return a.Cost < b.Cost
	}
	return a.Cost2 < b.Cost2
}

func routeEqualPref(a, b *Route) bool {
	return a.Type == b.Type && a.Cost == b.Cost && a.Cost2 == b.Cost2
}

// computeAll derives intra-area, inter-area and external routes from the
// given databases. It is pure: used both by real routers (on their LSDB) and
// by the reference model (on a globally-derived view).
func computeAll(r *Router, spts map[AreaID]*SPT, dbs map[AreaID]map[LSAKey]*LSA, ext map[LSAKey]*LSA) *RouteResult {
	res := &RouteResult{Intra: make(map[AreaID]map[Prefix]*Route), RIB: make(map[Prefix]*Route)}
	// 1. intra-area routes from stub links of every reachable router
	for _, area := range r.SortedAreas() {
		spt := spts[area]
		if spt == nil {
			continue
		}
		intra := make(map[Prefix]*Route)
		db := dbs[area]
		for _, k := range sortedKeys(db) {
			l := db[k]
			if l.Key.Type != LSARouter || l.Age(r.W.Now) >= r.W.Cfg.MaxAge {
				continue
			}
			d, ok := spt.Dist[l.Key.Adv]
			if !ok {
				continue
			}
			nh := spt.NextHops[l.Key.Adv]
			for _, lk := range l.RouterBody().Links {
				if lk.Type != LinkStub {
					continue
				}
				p := Prefix{Addr: lk.ID & lk.Data, Len: maskLen(lk.Data)}
				addRoute(intra, &Route{Prefix: p, Type: RouteIntra, Cost: d + lk.Metric, NextHops: nh})
			}
		}
		res.Intra[area] = intra
	}
	// merge intra into RIB
	for _, area := range r.SortedAreas() {
		for _, p := range sortedPrefixes(res.Intra[area]) {
			addRoute(res.RIB, res.Intra[area][p])
		}
	}
	// 2. inter-area routes from summary LSAs
	backboneAttached := false
	if s := spts[Backbone]; s != nil && len(s.Dist) > 1 {
		backboneAttached = true
	}
	var candAreas []AreaID
	if backboneAttached {
		candAreas = []AreaID{Backbone}
	} else {
		candAreas = r.SortedAreas()
	}
	for _, area := range candAreas {
		spt := spts[area]
		if spt == nil {
			continue
		}
		db := dbs[area]
		for _, k := range sortedKeys(db) {
			l := db[k]
			if l.Key.Type != LSASummary || l.Key.Adv == r.ID ||
				l.Age(r.W.Now) >= r.W.Cfg.MaxAge {
				continue
			}
			d, ok := spt.Dist[l.Key.Adv]
			if !ok {
				continue
			}
			body := l.SummaryBody()
			addRoute(res.RIB, &Route{
				Prefix:   body.Prefix,
				Type:     RouteInter,
				Cost:     d + body.Metric,
				NextHops: spt.NextHops[l.Key.Adv],
				Adv:      l.Key.Adv,
			})
		}
	}
	// 3. external routes
	for _, k := range sortedKeys(ext) {
		l := ext[k]
		if l.Key.Adv == r.ID || l.Age(r.W.Now) >= r.W.Cfg.MaxAge {
			continue
		}
		body := l.ExternalBody()
		asbr := l.Key.Adv
		internal := -1
		var nh []RouterID
		for _, area := range r.SortedAreas() {
			if spt := spts[area]; spt != nil {
				if d, ok := spt.Dist[asbr]; ok && (internal < 0 || d < internal) {
					internal = d
					nh = spt.NextHops[asbr]
				}
			}
		}
		if internal < 0 {
			if rt := res.RIB[Prefix{Addr: uint32(asbr), Len: 32}]; rt != nil && rt.Type == RouteInter {
				internal = rt.Cost
				nh = rt.NextHops
			}
		}
		if internal < 0 {
			continue
		}
		addRoute(res.RIB, &Route{
			Prefix:   body.Prefix,
			Type:     RouteExternal,
			Cost:     body.Metric,
			Cost2:    internal,
			NextHops: nh,
			Adv:      asbr,
		})
	}
	// 4. own static externals
	for _, st := range r.Statics {
		addRoute(res.RIB, &Route{Prefix: st.Prefix, Type: RouteExternal, Cost: st.Metric, Adv: r.ID})
	}
	return res
}

func sortedPrefixes(m map[Prefix]*Route) []Prefix {
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

// --- router SPF driving -----------------------------------------------------

func (r *Router) scheduleSPF(area AreaID) {
	if r.spfScheduled[area] {
		return
	}
	r.spfScheduled[area] = true
	w := r.W
	w.Schedule(w.Cfg.SpfDelay, false, "spf", func() { r.runSPF(area) })
}

func (r *Router) runSPF(area AreaID) {
	r.spfScheduled[area] = false
	db := r.LSDB[area]
	adj := buildAreaGraph(db, r.W.Now, r.W.Cfg.MaxAge)
	changes := r.linkChanges[area]
	r.linkChanges[area] = nil
	full := r.fullSPFOnly[area]
	r.fullSPFOnly[area] = false
	old := r.SPTs[area]
	var spt *SPT
	incremental := false
	if full || old == nil {
		spt = FullSPF(r.ID, adj)
	} else {
		spt = old
		iSPF(spt, adj, changes)
		incremental = true
	}
	if r.W.Cfg.Verify {
		ref := FullSPF(r.ID, adj)
		if !sptEqual(spt, ref) {
			panic(fmt.Sprintf("iSPF mismatch r=%s area=%d incremental=%v changes=%v",
				IDStr(r.ID), area, incremental, changes))
		}
	}
	r.SPTs[area] = spt
	r.recomputeRoutes()
}

func (r *Router) recomputeRoutes() {
	res := computeAll(r, r.SPTs, r.LSDB, r.ExtDB)
	r.IntraRoutes = res.Intra
	if !ribEqual(r.RIB, res.RIB) {
		r.RIB = res.RIB
		r.W.MarkChange()
	}
	r.updateSummaries()
	r.updateVLinks()
}

func ribEqual(a, b map[Prefix]*Route) bool {
	if len(a) != len(b) {
		return false
	}
	for p, ra := range a {
		rb := b[p]
		if rb == nil || ra.Type != rb.Type || ra.Cost != rb.Cost || ra.Cost2 != rb.Cost2 ||
			len(ra.NextHops) != len(rb.NextHops) {
			return false
		}
		for i := range ra.NextHops {
			if ra.NextHops[i] != rb.NextHops[i] {
				return false
			}
		}
	}
	return true
}
