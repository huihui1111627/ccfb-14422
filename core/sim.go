package core

import (
	"fmt"
	"sort"
	"strings"
)

// MakeRouterID builds a router id of the form 10.0.<hi>.<lo>.
func MakeRouterID(n int) RouterID {
	return RouterID(0x0A000000 | uint32(n))
}

// TopoSpec describes the random topology to generate.
type TopoSpec struct {
	AreaRouters map[AreaID]int // routers per area
	StubAreas   map[AreaID]bool
	TotallyStub map[AreaID]bool
	ExtraLinks  int // extra intra-area links beyond the spanning tree, per area
	ABRUplinks  int // ABR links per non-backbone area
	MTUBadLinks int // links with mismatched MTU
	ASBRs       int // routers originating external routes
	VirtualLink bool
}

// DefaultTopoSpec returns the standard lighthouse-network test topology.
func DefaultTopoSpec() TopoSpec {
	return TopoSpec{
		AreaRouters: map[AreaID]int{0: 8, 1: 12, 2: 10, 3: 8},
		StubAreas:   map[AreaID]bool{2: true},
		TotallyStub: map[AreaID]bool{3: true},
		ExtraLinks:  4,
		ABRUplinks:  2,
		MTUBadLinks: 2,
		ASBRs:       2,
		VirtualLink: true,
	}
}

// BuildRandomTopology generates a random multi-area topology.
func BuildRandomTopology(w *World, spec TopoSpec) {
	// create routers per area
	areaRouters := make(map[AreaID][]*Router)
	idx := 1
	var areas []int
	for a := range spec.AreaRouters {
		areas = append(areas, int(a))
	}
	sort.Ints(areas)
	for _, ai := range areas {
		a := AreaID(ai)
		if w.Areas[a] == nil {
			w.Areas[a] = &AreaConf{}
		}
		w.Areas[a].Stub = spec.StubAreas[a]
		w.Areas[a].TotallyStub = spec.TotallyStub[a]
		for i := 0; i < spec.AreaRouters[a]; i++ {
			r := w.NewRouter(MakeRouterID(idx))
			idx++
			areaRouters[a] = append(areaRouters[a], r)
		}
	}
	mtu := func() int { return 1500 }
	cost := func() int { return 1 + w.Rng.Intn(50) }
	delay := func() int64 { return 1 + int64(w.Rng.Intn(3)) }
	// spanning tree + extra links per area
	for _, ai := range areas {
		a := AreaID(ai)
		rs := areaRouters[a]
		for i := 1; i < len(rs); i++ {
			j := w.Rng.Intn(i)
			w.AddLink(rs[i], rs[j], a, cost(), delay(), mtu(), mtu())
		}
		for k := 0; k < spec.ExtraLinks; k++ {
			i, j := w.Rng.Intn(len(rs)), w.Rng.Intn(len(rs))
			if i == j {
				continue
			}
			w.AddLink(rs[i], rs[j], a, cost(), delay(), mtu(), mtu())
		}
	}
	// ABR uplinks: routers of non-backbone areas get a backbone-area link to a
	// backbone router. For area 1 the two uplinks land in different backbone
	// clusters so the virtual link is the only backbone connector.
	var nonBackbone []AreaID
	for _, ai := range areas {
		if AreaID(ai) != Backbone {
			nonBackbone = append(nonBackbone, AreaID(ai))
		}
	}
	bb := areaRouters[Backbone]
	half := len(bb) / 2
	var vlA, vlB *Router
	for _, a := range nonBackbone {
		rs := areaRouters[a]
		used := make(map[int]bool)
		for k := 0; k < spec.ABRUplinks; k++ {
			var abr *Router
			if a == 1 && spec.VirtualLink {
				// distinct endpoints for the virtual link
				for {
					i := w.Rng.Intn(len(rs))
					if !used[i] {
						used[i] = true
						abr = rs[i]
						break
					}
				}
			} else {
				abr = rs[w.Rng.Intn(len(rs))]
			}
			var bbr *Router
			if a == 1 && spec.VirtualLink {
				// split uplinks across the two backbone clusters
				if k%2 == 0 {
					bbr = bb[w.Rng.Intn(half)]
					vlA = abr
				} else {
					bbr = bb[half+w.Rng.Intn(len(bb)-half)]
					vlB = abr
				}
			} else {
				bbr = bb[w.Rng.Intn(len(bb))]
			}
			w.AddLink(abr, bbr, Backbone, cost(), delay(), mtu(), mtu())
		}
	}
	// virtual link across area 1 reconnecting the partitioned backbone
	if spec.VirtualLink && vlA != nil && vlB != nil {
		w.AddVLink(vlA, vlB, 1)
	}
	// a few links with mismatched MTU (adjacency will stall in ExStart)
	for k := 0; k < spec.MTUBadLinks; k++ {
		a := nonBackbone[w.Rng.Intn(len(nonBackbone))]
		rs := areaRouters[a]
		i, j := w.Rng.Intn(len(rs)), w.Rng.Intn(len(rs))
		if i == j {
			continue
		}
		w.AddLink(rs[i], rs[j], a, cost(), delay(), 1500, 1400)
	}
	// ASBRs with static external routes (in non-stub areas only)
	cands := append(append([]*Router{}, areaRouters[Backbone]...), areaRouters[1]...)
	for k := 0; k < spec.ASBRs && k < len(cands); k++ {
		r := cands[w.Rng.Intn(len(cands))]
		if r.ASBR {
			continue
		}
		r.ASBR = true
		r.Statics = append(r.Statics, ExternalLSABody{
			Prefix: Prefix{Addr: 0xC0A80000 | uint32(k+1)<<16, Len: 24}, // 192.168.k.0/24
			Metric: 20,
		})
	}
}

// RandomLinkOp performs one random topology change: a link goes down, a
// down link recovers, or a link cost changes. Returns a description.
func (w *World) RandomLinkOp() string {
	roll := w.Rng.Intn(100)
	var down, up []*Link
	for _, l := range w.Links {
		if l.Up {
			up = append(up, l)
		} else {
			down = append(down, l)
		}
	}
	switch {
	case roll < 40 && len(up) > 0:
		l := up[w.Rng.Intn(len(up))]
		w.SetLinkUp(l, false)
		return fmt.Sprintf("link %d (%s<->%s) DOWN", l.ID, IDStr(l.A.R.ID), IDStr(l.B.R.ID))
	case roll < 80 && len(down) > 0:
		l := down[w.Rng.Intn(len(down))]
		w.SetLinkUp(l, true)
		return fmt.Sprintf("link %d (%s<->%s) UP", l.ID, IDStr(l.A.R.ID), IDStr(l.B.R.ID))
	case len(up) > 0:
		l := up[w.Rng.Intn(len(up))]
		c := 1 + w.Rng.Intn(100)
		w.SetLinkCost(l, c)
		return fmt.Sprintf("link %d cost -> %d", l.ID, c)
	default:
		// every link is down: bring one back
		l := down[w.Rng.Intn(len(down))]
		w.SetLinkUp(l, true)
		return fmt.Sprintf("link %d (%s<->%s) UP", l.ID, IDStr(l.A.R.ID), IDStr(l.B.R.ID))
	}
}

// CompareRIBs diffs every router's RIB against the reference model.
// Returns a non-empty report on mismatch.
func (w *World) CompareRIBs() string {
	ref := w.ReferenceRIBs()
	var sb strings.Builder
	for _, r := range w.SortedRouters() {
		want := ref[r.ID]
		got := r.RIB
		for p, wr := range want {
			gr := got[p]
			if gr == nil {
				fmt.Fprintf(&sb, "r=%s MISSING %s want %s\n", IDStr(r.ID), p, wr)
				continue
			}
			if gr.Type != wr.Type || gr.Cost != wr.Cost || gr.Cost2 != wr.Cost2 ||
				len(gr.NextHops) != len(wr.NextHops) {
				fmt.Fprintf(&sb, "r=%s DIFF %s got %s want %s\n", IDStr(r.ID), p, gr, wr)
				continue
			}
			bad := false
			for i := range gr.NextHops {
				if gr.NextHops[i] != wr.NextHops[i] {
					bad = true
				}
			}
			if bad {
				fmt.Fprintf(&sb, "r=%s DIFF %s got %s want %s\n", IDStr(r.ID), p, gr, wr)
			}
		}
		for p, gr := range got {
			if want[p] == nil {
				fmt.Fprintf(&sb, "r=%s EXTRA %s got %s\n", IDStr(r.ID), p, gr)
			}
		}
	}
	return sb.String()
}
