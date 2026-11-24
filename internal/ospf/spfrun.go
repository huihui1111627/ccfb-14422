package ospf

import (
	"fmt"
	"sort"
)

// lsaChange records a single-router change in an area so the scheduler can
// take the incremental path instead of recomputing the whole graph.
type lsaChange struct {
	key    LSAKey
	oldLSA *LSA
	newLSA *LSA
}

// SPFStat describes one SPF run.
type SPFStat struct {
	Full    bool
	Changed uint32
	Nodes   int
	OldCost uint32
	NewCost uint32
}

func (st SPFStat) String() string {
	kind := "incremental"
	if st.Full {
		kind = "full"
	}
	return fmt.Sprintf("%s (%d nodes, changed %s %d -> %d)", kind, st.Nodes, u32ip(st.Changed), st.OldCost, st.NewCost)
}

// LastSPF returns the most recent run statistics for an area.
func (r *Router) LastSPF(area uint32) SPFStat { return r.lastSPF[area] }

// noteChange records an LSA change for an area. More than one changed router
// in the same batch degrades the entry to a full-run request.
func (r *Router) noteChange(area uint32, k LSAKey, oldL, newL *LSA) {
	if k.Type != LSARouter {
		// Summary and external advertisements do not change the intra-area
		// topology graph, so they must not trigger a shortest path
		// computation. They only require the route table to be rebuilt, which
		// the next RunSPF does once any real graph change settles.
		r.routesDirty = true
		return
	}
	r.spfDirty[area] = true
	r.changes[area] = append(r.changes[area], lsaChange{key: k, oldLSA: oldL, newLSA: newL})
}

// RunSPF processes every area that was marked dirty. The simulator calls this
// at the end of each packet batch.
func (r *Router) RunSPF(now int64) {
	areas := make([]uint32, 0, len(r.spfDirty))
	for a, d := range r.spfDirty {
		if d {
			areas = append(areas, a)
		}
	}
	// Non-backbone areas are computed first: the backbone's virtual links take
	// their cost from the transit area's shortest path tree, so that tree has
	// to be current before the backbone is computed.
	sort.Slice(areas, func(i, j int) bool {
		if (areas[i] == 0) != (areas[j] == 0) {
			return areas[j] == 0
		}
		return areas[i] < areas[j]
	})
	for _, area := range areas {
		r.runAreaSPF(area, now)
		r.spfDirty[area] = false
		delete(r.changes, area)
	}
	// A change in a transit area changes the cost and reachability of the
	// virtual links that tunnel through it, so a router that terminates a
	// virtual link must also recompute its backbone tree. This is the one
	// place where an area's result depends on another area, and it cannot be
	// expressed as a single-area incremental update; the backbone of a virtual
	// link endpoint is therefore recomputed in full, which is a handful of
	// nodes. Ordinary intra-area link changes still take the incremental path.
	if len(areas) > 0 && len(r.VirInterfaces) > 0 && !containsArea(areas, 0) {
		transitChanged := false
		for _, trans := range sortedAreaKeys(r.VirInterfaces) {
			if containsArea(areas, trans) {
				transitChanged = true
				break
			}
		}
		if transitChanged {
			r.changes[0] = nil
			r.spfDirty[0] = true
			r.runAreaSPF(0, now)
			r.spfDirty[0] = false
			delete(r.changes, 0)
		}
	}
	if len(areas) > 0 || r.routesDirty {
		r.recomputeRoutes()
		r.routesDirty = false
		if len(areas) > 0 {
			r.orchestrateAggregates(now)
		}
	}
	// Virtual links depend on the transit area's shortest path tree, which may
	// have just changed. Bring them up or down accordingly so their Hellos
	// only start once the transit path exists (requirement 7).
	r.refreshVirtualLinks(now)
}

// refreshVirtualLinks starts or stops each virtual interface according to
// whether the far endpoint is reachable through the transit area right now.
func (r *Router) refreshVirtualLinks(now int64) {
	for _, trans := range sortedAreaKeys(r.VirInterfaces) {
		for _, peer := range sortedPeerKeys(r.VirInterfaces[trans]) {
			i := r.VirInterfaces[trans][peer]
			res := r.spfArea[trans]
			reachable := res != nil
			if reachable {
				_, reachable = res.Dist[peer]
			}
			switch {
			case reachable && i.State == IfDown:
				r.virtualUp(i, now)
			case !reachable && i.State != IfDown:
				for _, n := range i.Nbrs {
					r.nbrEvent(i, n, NbrEventLLDown, now)
				}
				i.Nbrs = map[uint32]*Neighbour{}
				i.State = IfDown
				r.Audit.Event(now, EvArea, r.ID, 0, "virtual link %s down (transit area unreachable)", i.Name)
			}
		}
	}
}

// runAreaSPF decides between a full and an incremental computation.
//
// A single link cost change or link failure shows up as one or two changed
// router advertisements (the two ends of the link), and sometimes as a burst
// of a few. When every changed advertisement is for a router that was already
// reachable, the changes are applied one at a time through the dynamic SPF
// path; otherwise a full run is needed.
func (r *Router) runAreaSPF(area uint32, now int64) {
	chs := r.changes[area]
	old := r.spfArea[area]
	// A link change appears as one or two changed router advertisements (the
	// two endpoints), and a short burst is still a local change. Apply such
	// changes one at a time through the dynamic SPF path. Anything larger, or
	// any change to a router that is not reachable, is a topology change we
	// cannot bound cheaply, and a full run is correct.
	canIncremental := old != nil && len(chs) > 0 && len(chs) <= 4
	if canIncremental {
		for _, ch := range chs {
			if ch.key.Type != LSARouter || ch.oldLSA == nil {
				canIncremental = false
				break
			}
			if _, ok := old.Dist[ch.key.ID]; !ok {
				canIncremental = false
				break
			}
		}
	}
	if canIncremental {
		start := old.Dist[chs[0].key.ID]
		for _, ch := range chs {
			r.incrementalSPF(area, ch.key.ID, ch.oldLSA, ch.newLSA)
			old = r.spfArea[area]
		}
		nodes := len(r.spfArea[area].Dist)
		st := SPFStat{Nodes: nodes, Changed: chs[len(chs)-1].key.ID, OldCost: start}
		if d, ok := r.spfArea[area].Dist[chs[len(chs)-1].key.ID]; ok {
			st.NewCost = d
		}
		r.lastSPF[area] = st
		r.Audit.Event(now, EvSPF, r.ID, area, "incremental SPF: %d change(s), %d nodes", len(chs), nodes)
		return
	}
	r.runFullSPF(area)
	r.lastSPF[area] = SPFStat{Full: true, Nodes: len(r.spfArea[area].Dist)}
	if r.Audit != nil {
		r.Audit.Event(now, EvSPF, r.ID, area, "full SPF: %d nodes", len(r.spfArea[area].Dist))
	}
}

// ForceFullSPF recomputes an area from scratch (used by the verifier).
func (r *Router) ForceFullSPF(area uint32) { r.runFullSPF(area) }

func containsArea(areas []uint32, a uint32) bool {
	for _, x := range areas {
		if x == a {
			return true
		}
	}
	return false
}
