package core

import "testing"

func TestConvergenceRandomized(t *testing.T) {
	stats, err := RunConvergenceTrial(42, 300)
	if err != nil {
		t.Fatal(err)
	}
	var totEv, totTicks, maxEv, maxTicks int64
	for _, s := range stats {
		totEv += s.Events
		totTicks += s.Ticks
		if s.Events > maxEv {
			maxEv = s.Events
		}
		if s.Ticks > maxTicks {
			maxTicks = s.Ticks
		}
	}
	t.Logf("ops=%d avgEvents=%.1f maxEvents=%d avgTicks=%.1f maxTicks=%d",
		len(stats), float64(totEv)/float64(len(stats)), maxEv,
		float64(totTicks)/float64(len(stats)), maxTicks)
}

func TestConvergenceReproducible(t *testing.T) {
	s1, err1 := RunConvergenceTrial(7, 100)
	s2, err2 := RunConvergenceTrial(7, 100)
	if err1 != nil || err2 != nil {
		t.Fatalf("%v %v", err1, err2)
	}
	if len(s1) != len(s2) {
		t.Fatal("stat length mismatch")
	}
	for i := range s1 {
		if s1[i] != s2[i] {
			t.Fatalf("op %d differs between runs: %+v vs %+v", i, s1[i], s2[i])
		}
	}
}

func TestStubAndTotallyStubAreas(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Verify = true
	w := NewWorld(11, cfg)
	BuildRandomTopologyWith(w, func(spec *TopoSpec) {})
	if diff := w.CompareRIBs(); diff != "" {
		t.Fatalf("initial:\n%s", diff)
	}
	// find routers whose ONLY area is the stub (2) / totally-stub (3) area
	var stubR, tstR *Router
	for _, r := range w.SortedRouters() {
		if len(r.AreaSet) == 1 && r.AreaSet[2] && stubR == nil {
			stubR = r
		}
		if len(r.AreaSet) == 1 && r.AreaSet[3] && tstR == nil {
			tstR = r
		}
	}
	if stubR == nil || tstR == nil {
		t.Fatal("stub routers not found")
	}
	// stub area: default route present, no external routes, externals absent from ExtDB
	if stubR.RIB[defaultPrefix] == nil {
		t.Error("stub router has no default route")
	}
	for p, rt := range stubR.RIB {
		if rt.Type == RouteExternal {
			t.Errorf("stub router has external route %s", p)
		}
	}
	if len(stubR.ExtDB) != 0 {
		t.Errorf("stub router has %d external LSAs", len(stubR.ExtDB))
	}
	// totally stubby: default route, no inter-area routes except default
	if tstR.RIB[defaultPrefix] == nil {
		t.Error("totally-stub router has no default route")
	}
	for p, rt := range tstR.RIB {
		if rt.Type == RouteInter && p != defaultPrefix {
			t.Errorf("totally-stub router has inter-area route %s", p)
		}
		if rt.Type == RouteExternal {
			t.Errorf("totally-stub router has external route %s", p)
		}
	}
	// a backbone router should see external routes
	var bbR *Router
	for _, r := range w.SortedRouters() {
		if r.AreaSet[Backbone] && !r.AreaSet[1] && bbR == nil {
			bbR = r
		}
	}
	if bbR == nil {
		t.Fatal("no pure backbone router")
	}
	hasExt := false
	for _, rt := range bbR.RIB {
		if rt.Type == RouteExternal {
			hasExt = true
		}
	}
	if !hasExt {
		t.Error("backbone router has no external routes")
	}
}

// BuildRandomTopologyWith builds the default topology (helper for tests).
func BuildRandomTopologyWith(w *World, tweak func(*TopoSpec)) {
	spec := DefaultTopoSpec()
	tweak(&spec)
	BuildRandomTopology(w, spec)
	w.Boot()
	w.RunQuiescent()
}

func TestVirtualLinkReconnectsBackbone(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Verify = true
	w := NewWorld(11, cfg)
	BuildRandomTopologyWith(w, func(spec *TopoSpec) {})
	if len(w.VLs) == 0 {
		t.Skip("no virtual link in topology")
	}
	vl := w.VLs[0]
	na := w.Routers[vl.A].vlNeighbor(vl)
	nb := w.Routers[vl.B].vlNeighbor(vl)
	if na == nil || nb == nil || na.State != NbrFull || nb.State != NbrFull {
		st := func(n *Neighbor) string {
			if n == nil {
				return "nil"
			}
			return n.State.String()
		}
		t.Fatalf("virtual link not Full: %s / %s", st(na), st(nb))
	}
	// backbone routers from both clusters must reach each other (via the VL)
	if diff := w.CompareRIBs(); diff != "" {
		t.Fatalf("RIB mismatch with VL up:\n%s", diff)
	}
}
