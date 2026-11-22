package core

import (
	"strings"
	"testing"
)

func newTestWorld(seed int64) *World {
	cfg := DefaultConfig()
	cfg.Verify = true
	return NewWorld(seed, cfg)
}

// lineTopo builds a simple line of n routers in the backbone.
func lineTopo(w *World, n int) []*Router {
	var rs []*Router
	for i := 0; i < n; i++ {
		rs = append(rs, w.NewRouter(MakeRouterID(i+1)))
	}
	for i := 0; i+1 < n; i++ {
		w.AddLink(rs[i], rs[i+1], Backbone, 10, 1, 1500, 1500)
	}
	return rs
}

func TestNeighborReachesFull(t *testing.T) {
	w := newTestWorld(1)
	rs := lineTopo(w, 3)
	w.Boot()
	w.RunQuiescent()
	for _, r := range rs {
		for _, n := range r.AllNeighbors() {
			if n.State != NbrFull {
				t.Fatalf("router %s neighbor %s state %s, want Full",
					IDStr(r.ID), IDStr(n.RtrID), n.State)
			}
		}
	}
	// router 1 should reach router 3's loopback at cost 20
	r1 := w.Routers[MakeRouterID(1)]
	rt := r1.RIB[Prefix{Addr: uint32(MakeRouterID(3)), Len: 32}]
	if rt == nil || rt.Cost != 20 || rt.Type != RouteIntra {
		t.Fatalf("r1 route to r3: %+v", rt)
	}
	if diff := w.CompareRIBs(); diff != "" {
		t.Fatalf("RIB mismatch:\n%s", diff)
	}
}

func TestMTUMismatchStalls(t *testing.T) {
	w := newTestWorld(2)
	a := w.NewRouter(MakeRouterID(1))
	b := w.NewRouter(MakeRouterID(2))
	w.AddLink(a, b, Backbone, 10, 1, 1500, 1400)
	w.Boot()
	w.RunQuiescent()
	na := a.Ifaces[0].Nbr
	nb := b.Ifaces[0].Nbr
	if na == nil || nb == nil {
		t.Fatal("neighbors not created")
	}
	if na.State != NbrExStart || nb.State != NbrExStart {
		t.Fatalf("states: %s / %s, want both ExStart", na.State, nb.State)
	}
	if !strings.Contains(na.StuckReason, "MTU mismatch") {
		t.Fatalf("stuck reason: %q", na.StuckReason)
	}
	// no route to each other's loopback
	if _, ok := a.RIB[b.Loopback()]; ok {
		t.Fatal("unexpected route across MTU-mismatched link")
	}
}

func TestLinkDownUpReconverges(t *testing.T) {
	w := newTestWorld(3)
	rs := lineTopo(w, 4)
	w.Boot()
	w.RunQuiescent()
	if diff := w.CompareRIBs(); diff != "" {
		t.Fatalf("initial:\n%s", diff)
	}
	// cut the middle link
	w.SetLinkUp(w.Links[1], false)
	w.RunQuiescent()
	r1 := w.Routers[MakeRouterID(1)]
	if _, ok := r1.RIB[rs[3].Loopback()]; ok {
		t.Fatal("r1 should not reach r4 after cut")
	}
	if diff := w.CompareRIBs(); diff != "" {
		t.Fatalf("after cut:\n%s", diff)
	}
	// heal
	w.SetLinkUp(w.Links[1], true)
	w.RunQuiescent()
	if diff := w.CompareRIBs(); diff != "" {
		t.Fatalf("after heal:\n%s", diff)
	}
}

func TestLSARefreshAndMaxAge(t *testing.T) {
	w := newTestWorld(4)
	w.Cfg.RefreshTime = 100
	w.Cfg.MaxAge = 250
	rs := lineTopo(w, 2)
	w.Boot()
	w.RunQuiescent()
	r1, r2 := rs[0], rs[1]
	k := LSAKey{Type: LSARouter, LSID: uint32(r1.ID), Adv: r1.ID}
	seq0 := r2.LSDB[Backbone][k].Seq
	// let a few refresh cycles pass
	for i := 0; i < 5; i++ {
		w.Schedule(120, false, "nop", func() {})
		w.RunQuiescent()
	}
	l := r2.LSDB[Backbone][k]
	if l == nil {
		t.Fatal("r1 router LSA missing at r2")
	}
	if l.Seq <= seq0 {
		t.Fatalf("LSA not refreshed: seq %d -> %d", seq0, l.Seq)
	}
	if l.Age(w.Now) >= w.Cfg.MaxAge {
		t.Fatalf("self-originated LSA reached MaxAge: age %d", l.Age(w.Now))
	}
	// now kill r1's only link: r2's copy of r1's LSA must age out to MaxAge
	// (kept as a tombstone, excluded from routing)
	w.SetLinkUp(w.Links[0], false)
	w.RunQuiescent()
	for i := 0; i < 5; i++ {
		w.Schedule(120, false, "nop", func() {})
		w.RunQuiescent()
	}
	l = r2.LSDB[Backbone][k]
	if l == nil {
		t.Fatal("orphaned LSA tombstone missing")
	}
	if l.Age(w.Now) < w.Cfg.MaxAge {
		t.Fatalf("orphaned LSA not aged out: age %d", l.Age(w.Now))
	}
	// and it must not affect routing
	if _, ok := r2.RIB[r1.Loopback()]; ok {
		t.Fatal("route via MaxAge LSA still present")
	}
}

func TestOlderLSAGetsNewerCopyBack(t *testing.T) {
	w := newTestWorld(5)
	rs := lineTopo(w, 2)
	w.Boot()
	w.RunQuiescent()
	r1, r2 := rs[0], rs[1]
	k := LSAKey{Type: LSARouter, LSID: uint32(r1.ID), Adv: r1.ID}
	cur := r2.LSDB[Backbone][k]
	// forge an older instance of r1's LSA and inject it at r2 from r1's direction
	old := &LSA{Key: k, Seq: cur.Seq - 1, Body: cur.Body}
	old.Cksum = old.checksum()
	n := r2.Ifaces[0].Nbr
	r2.handleLSU(n, &Packet{Type: PktLSU, Src: r1.ID, LSAs: []*LSA{old}})
	w.RunQuiescent()
	got := r2.LSDB[Backbone][k]
	if got.Seq != cur.Seq {
		t.Fatalf("older LSA overwrote newer: seq %d, want %d", got.Seq, cur.Seq)
	}
	// r1 must have received the newer copy back (its own LSA reinstalled/flooded)
	if r1.LSDB[Backbone][k].Seq != cur.Seq {
		t.Fatalf("r1 did not get its newer LSA back: seq %d", r1.LSDB[Backbone][k].Seq)
	}
}
