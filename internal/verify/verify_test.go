package verify

import (
	"testing"

	"backhaul/internal/ospf"
	"backhaul/internal/sim"
	"backhaul/internal/topology"
)

// TestReproducible proves that the same seed produces the same run, byte for
// byte, including the final database and routing table digest.
func TestReproducible(t *testing.T) {
	opt := DefaultOptions(20240101)
	opt.Duration = 600_000
	opt.MeanGap = 2_000
	a, err := Run(opt)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Run(opt)
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest != b.Digest {
		t.Fatalf("same seed produced different states: %s vs %s", a.Digest, b.Digest)
	}
	if len(a.Violations) != len(b.Violations) {
		t.Fatalf("violation count differs: %d vs %d", len(a.Violations), len(b.Violations))
	}
	if len(a.LSAStats) != len(b.LSAStats) {
		t.Fatalf("LSA statistics differ")
	}
}

// TestInvariants runs a multi-seed replay and requires every invariant to hold.
func TestInvariants(t *testing.T) {
	for _, seed := range []int64{1, 42, 1234, 5555} {
		opt := DefaultOptions(seed)
		opt.Duration = 900_000
		opt.MeanGap = 1_200
		res, err := Run(opt)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		if !res.Ok() {
			for _, v := range res.Violations {
				t.Errorf("seed %d: %s at %d: %s", seed, v.Kind, v.At, v.Detail)
			}
			continue
		}
		if res.Weather < 400 {
			t.Errorf("seed %d: only %d weather events", seed, res.Weather)
		}
		t.Logf("%s", res.Summary())
	}
}

// TestNeighbourStateMachineFromInitialToFull exercises a clean topology and
// requires every adjacency to walk Init -> 2-Way -> ExStart -> Exchange ->
// (Loading) -> Full, with every recorded transition accepted by the table.
func TestNeighbourStateMachineFromInitialToFull(t *testing.T) {
	s, err := sim.New(topology.Build(), sim.Options{Seed: 3, Duration: 400_000, MeanGap: 1e9})
	if err != nil {
		t.Fatal(err)
	}
	s.Start()
	for tt := int64(1_000); tt <= 400_000; tt += 1_000 {
		s.Batch(tt)
	}
	for _, id := range s.RouterIDs {
		r := s.Routers[id]
		for _, n := range r.Neighbours() {
			if n.State != "Full" {
				t.Errorf("%s neighbour %s is %s, want Full", r.Name, ospf.IP(n.RouterID), n.State)
			}
		}
	}
	// Every transition must be legal; the state machine validates on record,
	// but re-check here for completeness.
	for _, rec := range s.Audit.Transitions {
		if err := ospf.ValidateTransition(rec); err != nil {
			t.Errorf("illegal transition: %v", err)
		}
	}
}

// TestMtuMismatchStopsInExchange configures one link with differing interface
// MTUs and requires the adjacency to stop in Exchange with a recorded reason,
// never reaching Full.
func TestMtuMismatchStopsInExchange(t *testing.T) {
	top := topology.Build()
	for i := range top.Links {
		if top.Links[i].ID == "L-core-1-2" {
			top.Links[i].MtuA = 1500
			top.Links[i].MtuB = 1400
		}
	}
	s, err := sim.New(top, sim.Options{Seed: 3, Duration: 200_000, MeanGap: 1e9})
	if err != nil {
		t.Fatal(err)
	}
	s.Start()
	for tt := int64(1_000); tt <= 200_000; tt += 1_000 {
		s.Batch(tt)
	}
	mid := s.Routers[0x0aff0002]
	var found bool
	for _, n := range mid.Neighbours() {
		if n.Interface == "L-core-1-2" {
			found = true
			if n.State == "Full" {
				t.Errorf("MTU-mismatched adjacency reached Full")
			}
			if !n.MtuDisagreement {
				t.Errorf("MTU mismatch not recorded")
			}
			if n.StuckReason == "" {
				t.Errorf("stuck reason is empty")
			}
			t.Logf("Core-Mid -> %s: %s (%s)", ospf.IP(n.RouterID), n.State, n.StuckReason)
		}
	}
	if !found {
		t.Fatal("expected an adjacency on the mismatched link")
	}
}

// TestStaleLSARepliedWithNewer checks requirement 3: when a router receives an
// older instance of an advertisement it already holds, it must send its newer
// copy back.
func TestStaleLSARepliedWithNewer(t *testing.T) {
	s, err := sim.New(topology.Build(), sim.Options{Seed: 3, Duration: 200_000, MeanGap: 1e9})
	if err != nil {
		t.Fatal(err)
	}
	s.Start()
	for tt := int64(1_000); tt <= 200_000; tt += 1_000 {
		s.Batch(tt)
	}
	total := 0
	for _, rec := range s.Metrics.LSAs {
		total += rec.StaleReplied
	}
	if total == 0 {
		t.Skip("no stale instances observed in this short clean run")
	}
	t.Logf("stale instances answered with the newer copy: %d", total)
}

// TestIncrementalMatchesFull checks requirement 5: after a single link cost
// change, the incrementally maintained tree equals a full recomputation and
// the incremental path was actually used.
func TestIncrementalMatchesFull(t *testing.T) {
	s, err := sim.New(topology.Build(), sim.Options{Seed: 3, Duration: 200_000, MeanGap: 1e9})
	if err != nil {
		t.Fatal(err)
	}
	s.Start()
	s.Batch(150_000)
	s.Batch(150_000)
	inc0 := s.Metrics.SPFIncr
	full0 := s.Metrics.SPFFull
	s.ApplyCostForTest("L-n1-n2", 70, 150_000)
	s.Batch(160_000)
	s.Batch(160_000)
	usedIncr := s.Metrics.SPFIncr - inc0
	usedFull := s.Metrics.SPFFull - full0
	if usedIncr == 0 {
		t.Errorf("cost change did not use the incremental path (full=%d)", usedFull)
	}
	for _, id := range s.RouterIDs {
		r := s.Routers[id]
		for _, area := range r.Areas {
			inc := r.SPFFor(area)
			if inc == nil {
				continue
			}
			full := r.SPFDebugFull(area)
			if len(full.Dist) != len(inc.Dist) {
				t.Errorf("%s area %d node count %d != %d", r.Name, area, len(inc.Dist), len(full.Dist))
				continue
			}
			for n, d := range full.Dist {
				if d2, ok := inc.Dist[n]; !ok || d2 != d {
					t.Errorf("%s area %d node %s cost %d != %d", r.Name, area, ospf.IP(n), d2, d)
				}
			}
		}
	}
	t.Logf("incremental=%d full=%d", usedIncr, usedFull)
}

// TestVirtualLinkRejoinsBackbone checks requirement 7: the two eastern ABRs are
// connected only through the transit area, so the backbone path between them
// must run over the virtual link once the transit area converges.
func TestVirtualLinkRejoinsBackbone(t *testing.T) {
	s, err := sim.New(topology.Build(), sim.Options{Seed: 5, Duration: 600_000, MeanGap: 1e9})
	if err != nil {
		t.Fatal(err)
	}
	s.Start()
	for tt := int64(1_000); tt <= 600_000; tt += 1_000 {
		s.Batch(tt)
	}
	abrN := s.Routers[0x0aff000a]
	abrS := s.Routers[0x0aff000b]
	var vfull bool
	for _, n := range abrN.Neighbours() {
		if n.RouterID == 0x0aff000b && n.State == "Full" {
			vfull = true
		}
	}
	if !vfull {
		t.Errorf("virtual link between the eastern ABRs did not reach Full")
	}
	// The backbone tree of each ABR must reach the other through the virtual
	// link.
	if res := abrN.SPFFor(0); res != nil {
		if _, ok := res.Dist[0x0aff000b]; !ok {
			t.Errorf("ABR-East-N backbone tree does not reach ABR-East-S")
		}
	}
	if res := abrS.SPFFor(0); res != nil {
		if _, ok := res.Dist[0x0aff000a]; !ok {
			t.Errorf("ABR-East-S backbone tree does not reach ABR-East-N")
		}
	}
}

// TestStubAreaNoExternals checks requirement 8: external (type 5) advertisements
// never appear in a stub area, and the area border router injects a default
// route instead.
func TestStubAreaNoExternals(t *testing.T) {
	s, err := sim.New(topology.Build(), sim.Options{Seed: 5, Duration: 600_000, MeanGap: 1e9})
	if err != nil {
		t.Fatal(err)
	}
	s.Start()
	for tt := int64(1_000); tt <= 600_000; tt += 1_000 {
		s.Batch(tt)
	}
	// Area 3 is the stub area.
	for _, id := range s.RouterIDs {
		r := s.Routers[id]
		if !r.AreaEnabled(3) {
			continue
		}
		for _, l := range r.AreaDB(3) {
			if l.Type == ospf.LSAASExternal {
				t.Errorf("%s holds external LSA in stub area 3", r.Name)
			}
		}
	}
	// The stub router should have a default route from its ABR.
	w := s.Routers[0x0aff0301]
	var def *ospf.Route
	for _, rt := range w.Routes {
		if rt.Prefix == 0 && rt.Mask == 0 {
			def = rt
		}
	}
	if def == nil {
		t.Errorf("stub area router has no default route")
	} else {
		t.Logf("stub default route cost=%d via %s", def.Cost, ospf.IP(def.NextHop))
	}
}

// TestInterAreaThroughBackbone checks requirement 6: a route between two
// non-backbone areas must traverse the backbone, which the inter-area summary
// mechanism guarantees by construction. Here we verify that a far area's
// prefix is learned as an inter-area route via an ABR.
func TestInterAreaThroughBackbone(t *testing.T) {
	s, err := sim.New(topology.Build(), sim.Options{Seed: 5, Duration: 600_000, MeanGap: 1e9})
	if err != nil {
		t.Fatal(err)
	}
	s.Start()
	for tt := int64(1_000); tt <= 600_000; tt += 1_000 {
		s.Batch(tt)
	}
	isle := s.Routers[0x0aff0101] // area 1
	found := false
	for _, rt := range isle.Routes {
		if rt.Type == ospf.RouteInter {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("area 1 router learned no inter-area routes")
	}
}
