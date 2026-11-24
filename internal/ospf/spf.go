package ospf

import (
	"container/heap"
	"sort"
)

// RouteType follows the OSPF path preference order.
type RouteType uint8

const (
	RouteIntra RouteType = iota
	RouteInter
	RouteExternal
)

func (t RouteType) String() string {
	switch t {
	case RouteIntra:
		return "intra"
	case RouteInter:
		return "inter"
	case RouteExternal:
		return "external"
	}
	return "?"
}

// Route is one entry of a router's OSPF routing table.
type Route struct {
	Prefix  uint32
	Mask    uint32
	Cost    uint32
	NextHop uint32 // router ID of the first hop; 0 means directly connected
	Area    uint32 // area the path was learned in
	Type    RouteType
	Origin  uint32 // advertising router (ABR/ASBR) or self
	// ViaBackbone records whether an inter-area path traverses area 0.
	ViaBackbone bool
	// Virtual marks routes that ride a virtual link.
	Virtual bool
	// Path is the router-level path within the area, for the topology view.
	Path []uint32
}

func (r *Route) String() string {
	return pfx(r.Prefix, r.Mask)
}

func pfx(net, mask uint32) string {
	return u32ip(net) + "/" + itoa(maskBits(mask))
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// edge is a directed adjacency in the router-only SPF graph.
type edge struct {
	to   uint32
	cost uint16
	kind uint8
}

// SPFResult is the per-area shortest path tree plus the derived routes.
type SPFResult struct {
	Area     uint32
	Dist     map[uint32]uint32
	Parent   map[uint32]uint32
	Children map[uint32][]uint32
	NextHop  map[uint32]uint32
	Edges    map[uint32][]edge
	Routes   []*Route
}

// edgesFromLSA extracts the directed edges advertised by a router LSA.
func edgesFromLSA(l *LSA) []edge {
	if l == nil || l.Type != LSARouter || l.Age >= MaxAge {
		return nil
	}
	var out []edge
	for _, ln := range DecodeRouterLinks(l.Body) {
		if ln.Type == LinkP2P || ln.Type == LinkVirtual {
			out = append(out, edge{to: ln.ID, cost: ln.Metric, kind: ln.Type})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].to != out[j].to {
			return out[i].to < out[j].to
		}
		return out[i].cost < out[j].cost
	})
	return out
}

// graphFor builds the current SPF graph for an area from the LSDB.
func (r *Router) graphFor(area uint32) map[uint32][]edge {
	g := map[uint32][]edge{}
	for k, l := range r.areaDB[area] {
		if k.Type != LSARouter || l.Age >= MaxAge {
			continue
		}
		g[k.ID] = edgesFromLSA(l)
		if _, ok := g[k.ID]; !ok {
			g[k.ID] = nil
		}
	}
	if area == 0 {
		// Virtual links are logical backbone links. Their cost is the
		// intra-area distance through the transit area (requirement 7).
		for vi := range r.Topo.Virtual {
			v := &r.Topo.Virtual[vi]
			if v.A == 0 && v.B == 0 {
				continue
			}
			have := false
			for _, e := range g[v.A] {
				if e.to == v.B {
					have = true
				}
			}
			if have {
				continue
			}
			if c, ok := r.TransitCost(v); ok {
				g[v.A] = append(g[v.A], edge{to: v.B, cost: c, kind: LinkVirtual})
				g[v.B] = append(g[v.B], edge{to: v.A, cost: c, kind: LinkVirtual})
			}
		}
	}
	return g
}

type pqItem struct {
	id   uint32
	dist uint32
}

type pq []pqItem

func (p pq) Len() int { return len(p) }
func (p pq) Less(i, j int) bool {
	if p[i].dist != p[j].dist {
		return p[i].dist < p[j].dist
	}
	return p[i].id < p[j].id
}
func (p pq) Swap(i, j int) { p[i], p[j] = p[j], p[i] }
func (p *pq) Push(x any)   { *p = append(*p, x.(pqItem)) }
func (p *pq) Pop() any {
	old := *p
	n := len(old)
	it := old[n-1]
	*p = old[:n-1]
	return it
}

// fullSPF runs Dijkstra from the router itself over the area graph.
func (r *Router) fullSPF(area uint32) *SPFResult {
	g := r.graphFor(area)
	res := &SPFResult{
		Area:     area,
		Dist:     map[uint32]uint32{},
		Parent:   map[uint32]uint32{},
		Children: map[uint32][]uint32{},
		NextHop:  map[uint32]uint32{},
		Edges:    g,
	}
	res.Dist[r.ID] = 0
	q := &pq{{id: r.ID, dist: 0}}

	heap.Init(q)
	for q.Len() > 0 {
		it := heap.Pop(q).(pqItem)
		if d, ok := res.Dist[it.id]; ok && it.dist > d {
			continue
		}
		for _, e := range g[it.id] {
			nd := it.dist + uint32(e.cost)
			if old, ok := res.Dist[e.to]; !ok || nd < old {
				res.Dist[e.to] = nd
				heap.Push(q, pqItem{id: e.to, dist: nd})
			}
		}
	}
	r.finishSPF(res, g, area)
	return res
}

// finishSPF canonicalises the shortest path tree and derives routes. The
// parent of a node is chosen deterministically among all neighbours that
// explain its distance: smallest (parent distance, parent id). Both the full
// and the incremental computation pass through this routine, so the two trees
// are identical by construction.
func (r *Router) finishSPF(res *SPFResult, g map[uint32][]edge, area uint32) {
	res.Children = map[uint32][]uint32{}
	res.NextHop = map[uint32]uint32{}
	res.Parent = map[uint32]uint32{}
	// Reverse adjacency: for every edge v->x record v as a candidate parent.
	incoming := map[uint32][]uint32{}
	for v, es := range g {
		if d, ok := res.Dist[v]; !ok || d == ^uint32(0) {
			continue
		}
		for _, e := range es {
			if _, ok := res.Dist[e.to]; !ok {
				continue
			}
			incoming[e.to] = append(incoming[e.to], v)
		}
	}
	for x := range res.Dist {
		if x == r.ID || res.Dist[x] == ^uint32(0) {
			continue
		}
		bestV := uint32(0)
		bestKey := [2]uint32{^uint32(0), ^uint32(0)}
		for _, v := range incoming[x] {
			w := edgeCost(g, v, x)
			if w < 0 {
				continue
			}
			dv := res.Dist[v]
			if dv == ^uint32(0) || dv+uint32(w) != res.Dist[x] {
				continue
			}
			if k := [2]uint32{dv, v}; k[0] < bestKey[0] || (k[0] == bestKey[0] && k[1] < bestKey[1]) {
				bestKey = k
				bestV = v
			}
		}
		if bestV != 0 {
			res.Parent[x] = bestV
		}
	}
	for id, p := range res.Parent {
		if id != r.ID && p != 0 {
			res.Children[p] = append(res.Children[p], id)
		}
	}
	for id := range res.Children {
		sort.Slice(res.Children[id], func(i, j int) bool { return res.Children[id][i] < res.Children[id][j] })
	}
	var nh func(id uint32) uint32
	nh = func(id uint32) uint32 {
		p, ok := res.Parent[id]
		if !ok || p == 0 || id == r.ID {
			return r.ID
		}
		if p == r.ID {
			return id
		}
		return nh(p)
	}
	for id := range res.Dist {
		if res.Dist[id] == ^uint32(0) {
			continue
		}
		res.NextHop[id] = nh(id)
	}
	res.Routes = r.routesFromSPF(res)
}

// edgeCost returns the cheapest parallel edge v->x, or -1 when none exists.
func edgeCost(g map[uint32][]edge, v, x uint32) int {
	best := -1
	for _, e := range g[v] {
		if e.to != x {
			continue
		}
		if best < 0 || int(e.cost) < best {
			best = int(e.cost)
		}
	}
	return best
}

// pathTo reconstructs the router-level path from the root to id.
func (res *SPFResult) pathTo(id uint32) []uint32 {
	var rev []uint32
	seen := map[uint32]bool{}
	for cur := id; cur != 0 && !seen[cur]; {
		seen[cur] = true
		rev = append(rev, cur)
		p, ok := res.Parent[cur]
		if !ok || p == 0 || p == cur {
			break
		}
		cur = p
	}
	out := make([]uint32, 0, len(rev))
	for i := len(rev) - 1; i >= 0; i-- {
		out = append(out, rev[i])
	}
	return out
}

// routesFromSPF turns reachable routers' stub links into intra-area routes.
func (r *Router) routesFromSPF(res *SPFResult) []*Route {
	var out []*Route
	for id, d := range res.Dist {
		l := r.areaDB[res.Area][LSAKey{LSARouter, id, id}]
		if l == nil {
			continue
		}
		for _, ln := range DecodeRouterLinks(l.Body) {
			if ln.Type != LinkStub {
				continue
			}
			rt := &Route{
				Prefix:  ln.ID & ln.Data,
				Mask:    ln.Data,
				Cost:    d + uint32(ln.Metric),
				NextHop: res.NextHop[id],
				Area:    res.Area,
				Type:    RouteIntra,
				Origin:  id,
				Path:    res.pathTo(id),
			}
			if id == r.ID {
				rt.NextHop = 0
			}
			out = append(out, rt)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Prefix != out[j].Prefix {
			return out[i].Prefix < out[j].Prefix
		}
		return maskBits(out[i].Mask) > maskBits(out[j].Mask)
	})
	return out
}

// ---- Incremental SPF ------------------------------------------------------

// incrementalSPF recomputes only the part of the shortest path tree that the
// change of one router advertisement can affect (requirement 5).
//
// The algorithm is the dynamic-SPF "affected subtree" method and compares the
// graph as it stood at the last SPF run with the current graph, so it also
// catches logical changes such as a virtual link appearing or disappearing
// when its transit area becomes reachable:
//
//  1. Edges that disappeared or grew more expensive can only lengthen paths.
//     Every node whose old shortest path used such an edge, together with its
//     whole old subtree, is marked for recomputation.
//  2. Edges that appeared or got cheaper can only shorten paths. They and the
//     valid boundary of the invalidated set seed a Dijkstra run restricted to
//     the invalidated nodes.
//
// Nodes outside the affected set keep their distances: every alternative
// path to them is at least as expensive. finishSPF then derives parents, next
// hops and routes canonically, so the incremental tree equals a full one.
func (r *Router) incrementalSPF(area uint32, changed uint32, oldL, newL *LSA) {
	old := r.spfArea[area]
	if old == nil || old.Edges == nil {
		r.runFullSPF(area)
		return
	}
	g := r.graphFor(area)
	oldCost := bestEdges(old.Edges)
	newCost := bestEdges(g)

	// If the set of nodes in the graph changed (a router appeared or vanished,
	// or a virtual link brought a new router into the backbone), the affected
	// set is hard to bound cheaply. A full run is correct and rare, because
	// ordinary cost and link changes keep the node set. Also require that the
	// stored tree was computed from the same node set as the graph it is being
	// updated against; otherwise the incremental path has no valid base.
	if !sameNodeSet(g, old.Edges) {
		r.runFullSPF(area)
		return
	}
	reachable := 0
	for id := range g {
		if _, ok := old.Dist[id]; ok {
			reachable++
		}
	}
	if reachable != len(old.Dist) {
		// The stored tree is missing nodes that are now present, or holds
		// nodes that left. Recompute from scratch.
		r.runFullSPF(area)
		return
	}
	raised := map[[2]uint32]bool{}
	improved := map[[2]uint32]bool{}
	for e, oc := range oldCost {
		nc, ok := newCost[e]
		if !ok || nc > oc {
			raised[e] = true
		} else if nc < oc {
			improved[e] = true
		}
	}
	for e := range newCost {
		if _, ok := oldCost[e]; !ok {
			improved[e] = true
		}
	}

	const inf = ^uint32(0)
	res := &SPFResult{
		Area:     area,
		Dist:     map[uint32]uint32{},
		Children: map[uint32][]uint32{},
		NextHop:  map[uint32]uint32{},
		Edges:    g,
	}
	for k, v := range old.Dist {
		res.Dist[k] = v
	}

	// Step 1: invalidate subtrees that hung off a raised or removed edge.
	removed := map[uint32]bool{}
	var mark func(id uint32)
	mark = func(id uint32) {
		if removed[id] {
			return
		}
		removed[id] = true
		res.Dist[id] = inf
		for _, c := range old.Children[id] {
			mark(c)
		}
	}
	for e := range raised {
		from, to := e[0], e[1]
		if p, ok := old.Parent[to]; ok && p == from {
			mark(to)
		}
	}
	// A node that left the graph entirely, or that was unreachable before but
	// now has edges, is also invalidated.
	for _, id := range sortedDistKeys(old.Dist) {
		if _, ok := g[id]; !ok {
			mark(id)
		}
	}
	for id := range g {
		if _, ok := old.Dist[id]; !ok {
			removed[id] = true
			res.Dist[id] = inf
		}
	}

	q := &pq{}
	heap.Init(q)
	push := func(id uint32, d uint32) {
		if cur, ok := res.Dist[id]; !ok || d < cur {
			res.Dist[id] = d
			heap.Push(q, pqItem{id: id, dist: d})
		}
	}
	// Cheaper or new edges from still-valid nodes.
	for e := range improved {
		from, to := e[0], e[1]
		if removed[from] {
			continue
		}
		d, ok := res.Dist[from]
		if !ok || d == inf {
			continue
		}
		push(to, d+uint32(newCost[e]))
	}
	// Boundary of the invalidated set: valid node -> invalidated node.
	for _, id := range sortedU32Set(removed) {
		for _, v := range incomingNeighbours(g, id) {
			if removed[v] {
				continue
			}
			dv := res.Dist[v]
			if dv == inf {
				continue
			}
			if c := edgeCost(g, v, id); c >= 0 {
				push(id, dv+uint32(c))
			}
		}
	}
	for q.Len() > 0 {
		it := heap.Pop(q).(pqItem)
		if it.dist > res.Dist[it.id] {
			continue
		}
		for _, e := range g[it.id] {
			nd := it.dist + uint32(e.cost)
			if cur, ok := res.Dist[e.to]; !ok || cur == inf || nd < cur {
				res.Dist[e.to] = nd
				heap.Push(q, pqItem{id: e.to, dist: nd})
			}
		}
	}
	for id, d := range res.Dist {
		if d == inf {
			delete(res.Dist, id)
		}
	}
	// Reachability is cheap to recompute and is the one thing the affected
	// subtree method must get exactly right. If the resulting distance map
	// does not cover precisely the nodes reachable from us in the current
	// graph, fall back to a full run rather than ship a wrong tree.
	if !sameReachability(res.Dist, reachableSet(g, r.ID)) {
		r.runFullSPF(area)
		return
	}
	r.Metrics.SPFIncr++
	r.finishSPF(res, g, area)
	r.spfArea[area] = res
	r.recomputeRoutes()
}

// reachableSet is a breadth first traversal of the graph from root.
func reachableSet(g map[uint32][]edge, root uint32) map[uint32]bool {
	seen := map[uint32]bool{root: true}
	queue := []uint32{root}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range g[cur] {
			if !seen[e.to] {
				seen[e.to] = true
				queue = append(queue, e.to)
			}
		}
	}
	return seen
}

// sameReachability reports whether dist covers exactly the reachable nodes.
func sameReachability(dist map[uint32]uint32, reach map[uint32]bool) bool {
	if len(dist) != len(reach) {
		return false
	}
	for id := range reach {
		if _, ok := dist[id]; !ok {
			return false
		}
	}
	return true
}

// bestEdges collapses parallel edges into the cheapest cost per direction.
func bestEdges(g map[uint32][]edge) map[[2]uint32]uint16 {
	out := map[[2]uint32]uint16{}
	for v, es := range g {
		for _, e := range es {
			k := [2]uint32{v, e.to}
			if c, ok := out[k]; !ok || e.cost < c {
				out[k] = e.cost
			}
		}
	}
	return out
}

func sortedDistKeys(m map[uint32]uint32) []uint32 {
	out := make([]uint32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// bestEdgeCost collapses a link list into the cheapest cost per neighbour.
func bestEdgeCost(es []edge) map[uint32]uint16 {
	out := map[uint32]uint16{}
	for _, e := range es {
		if c, ok := out[e.to]; !ok || e.cost < c {
			out[e.to] = e.cost
		}
	}
	return out
}

// incomingNeighbours lists every router with an edge into id.
func incomingNeighbours(g map[uint32][]edge, id uint32) []uint32 {
	var out []uint32
	for v, es := range g {
		for _, e := range es {
			if e.to == id {
				out = append(out, v)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedU32Set(m map[uint32]bool) []uint32 {
	out := make([]uint32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// runFullSPF recomputes an area from scratch and stores the result.
func (r *Router) runFullSPF(area uint32) {
	res := r.fullSPF(area)
	r.Metrics.SPFFull++
	r.Metrics.SPFRuns++
	r.spfArea[area] = res
	r.recomputeRoutes()
}

// SPFDebugFull returns a full recomputation without touching state; the
// verifier compares it against the incrementally maintained tree.
func (r *Router) SPFDebugFull(area uint32) *SPFResult { return r.fullSPF(area) }

// SPFFor returns the stored SPF result for an area.
func (r *Router) SPFFor(area uint32) *SPFResult { return r.spfArea[area] }

// recomputeRoutes rebuilds the routing table from all areas.
func (r *Router) recomputeRoutes() {
	var all []*Route
	for _, area := range sortedSPFKeys(r.spfArea) {
		res := r.spfArea[area]
		if res == nil {
			continue
		}
		all = append(all, res.Routes...)
	}
	all = append(all, r.interAreaRoutes()...)
	all = append(all, r.externalRoutes()...)
	r.Routes = selectBest(all)
}

func sortedSPFKeys(m map[uint32]*SPFResult) []uint32 {
	out := make([]uint32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// selectBest keeps one route per prefix using OSPF preference and cost.
func selectBest(in []*Route) []*Route {
	best := map[[2]uint32]*Route{}
	for _, rt := range in {
		k := [2]uint32{rt.Prefix & rt.Mask, rt.Mask}
		cur := best[k]
		if cur == nil || better(rt, cur) {
			best[k] = rt
		}
	}
	out := make([]*Route, 0, len(best))
	for _, rt := range best {
		out = append(out, rt)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Cost != out[j].Cost {
			return out[i].Cost < out[j].Cost
		}
		if out[i].Prefix != out[j].Prefix {
			return out[i].Prefix < out[j].Prefix
		}
		return maskBits(out[i].Mask) > maskBits(out[j].Mask)
	})
	return out
}

func better(a, b *Route) bool {
	if a.Type != b.Type {
		return a.Type < b.Type
	}
	if a.Cost != b.Cost {
		return a.Cost < b.Cost
	}
	return a.Origin < b.Origin
}

// sameNodeSet reports whether two graphs have exactly the same vertices.
func sameNodeSet(a, b map[uint32][]edge) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}
