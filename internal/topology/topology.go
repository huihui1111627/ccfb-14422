// Package topology contains the example sea-area lighthouse network used by
// the demo, the verifier and the web page.
package topology

import (
	"fmt"

	"backhaul/internal/ospf"
)

// Build returns the reference topology.
//
// Layout (areas):
//
//	Area 0 (backbone)  : core relay stations along the coast
//	Area 1 (north isles): stub-ish northern cluster, one ABR to the backbone
//	Area 2 (south reef) : southern cluster, one ABR to the backbone
//	Area 3 (stub)       : isolated weather station cluster, stub area
//
// The backbone is deliberately split by area 4 in the "virtual" profile so a
// virtual link can rejoin it.
func Build() *ospf.Topology {
	t := &ospf.Topology{}
	add := func(name, ip string, x, y float64, asbr bool, primary uint32, ext ...string) uint32 {
		id := mustIP(ip)
		rc := ospf.RouterConfig{ID: id, Name: name, X: x, Y: y, IsASBR: asbr, PrimaryArea: primary}
		for _, e := range ext {
			rc.Externals = append(rc.Externals, parsePrefix(e))
		}
		t.Routers = append(t.Routers, rc)
		return id
	}
	// Backbone core relay stations.
	core1 := add("Core-North", "10.255.0.1", 320, 120, false, 0)
	core2 := add("Core-Mid", "10.255.0.2", 400, 260, false, 0)
	core3 := add("Core-South", "10.255.0.3", 360, 420, false, 0)
	// Area 1: northern isles.
	n1 := add("Isle-A", "10.255.1.1", 120, 60, false, 1)
	n2 := add("Isle-B", "10.255.1.2", 200, 40, false, 1)
	n3 := add("Isle-C", "10.255.1.3", 120, 200, false, 1)
	// Area 2: southern reef.
	s1 := add("Reef-A", "10.255.2.1", 560, 380, false, 2)
	s2 := add("Reef-B", "10.255.2.2", 560, 500, false, 2)
	s3 := add("Reef-C", "10.255.2.3", 460, 560, true, 2, "198.51.100.0/24")
	// Area 3: stub weather stations.
	w1 := add("Weather-1", "10.255.3.1", 140, 480, false, 3)
	w2 := add("Weather-2", "10.255.3.2", 120, 600, false, 3)
	// Area 4: eastern relay, isolated from the backbone except via a virtual
	// link. The two ABRs R4A and R4B also have backbone interfaces, but the
	// backbone path between them is cut by design (no direct link), forcing
	// the virtual link through area 4.
	r4a := add("ABR-East-N", "10.255.0.10", 520, 160, false, 0)
	r4b := add("ABR-East-S", "10.255.0.11", 520, 480, false, 0)
	e1 := add("East-1", "10.255.4.1", 640, 260, false, 4)
	e2 := add("East-2", "10.255.4.2", 680, 360, false, 4)

	link := func(id string, a, b uint32, area uint32, cost uint16, mtuA, mtuB int) {
		t.Links = append(t.Links, ospf.LinkConfig{ID: id, A: a, B: b, Area: area, Cost: cost, MtuA: mtuA, MtuB: mtuB, Nominal: 10})
	}
	c := 10
	// Backbone chain.
	link("L-core-1-2", core1, core2, 0, uint16(c), 1500, 1500)
	link("L-core-2-3", core2, core3, 0, uint16(c), 1500, 1500)
	// Area 1 attaches at core1.
	link("L-core1-n1", core1, n1, 1, 10, 1500, 1500)
	link("L-n1-n2", n1, n2, 1, 10, 1500, 1500)
	link("L-n1-n3", n1, n3, 1, 15, 1500, 1500)
	// Area 2 attaches at core3.
	link("L-core3-s1", core3, s1, 2, 10, 1500, 1500)
	link("L-s1-s2", s1, s2, 2, 10, 1500, 1500)
	link("L-s1-s3", s1, s3, 2, 12, 1500, 1500)
	// Area 3 (stub) attaches at core3 through Weather-1.
	link("L-core3-w1", core3, w1, 3, 20, 1500, 1500)
	link("L-w1-w2", w1, w2, 3, 10, 1500, 1500)
	// Area 4 attaches at r4a (north) and r4b (south).
	link("L-r4a-e1", r4a, e1, 4, 10, 1500, 1500)
	link("L-e1-e2", e1, e2, 4, 10, 1500, 1500)
	link("L-e2-r4b", e2, r4b, 4, 10, 1500, 1500)
	// Backbone attachments for the eastern ABRs.
	link("L-core1-r4a", core1, r4a, 0, 10, 1500, 1500)
	link("L-core3-r4b", core3, r4b, 0, 10, 1500, 1500)

	// Requirement 7: the backbone is split between the northern core and the
	// eastern ABRs. The two eastern ABRs also sit in area 4, so a virtual link
	// across area 4 rejoins the backbone (R4A <-> R4B). Without it, area 1 and
	// area 2 would each see only part of the backbone.
	t.Virtual = []ospf.VirtualLinkConfig{
		{ID: "VL-east", A: r4a, B: r4b, Transit: 4, Nominal: 20},
	}

	t.Areas = []ospf.AreaConfig{
		{ID: 0, Type: ospf.NormalArea},
		{ID: 1, Type: ospf.NormalArea},
		{ID: 2, Type: ospf.NormalArea},
		{ID: 3, Type: ospf.StubArea},
		{ID: 4, Type: ospf.NormalArea},
	}
	return t
}

func mustIP(s string) uint32 {
	var a, b, c, d uint32
	if _, err := fmt.Sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d); err != nil {
		panic(err)
	}
	return a<<24 | b<<16 | c<<8 | d
}

func parsePrefix(s string) ospf.Prefix {
	var a, b, c, d, bits uint32
	if _, err := fmt.Sscanf(s, "%d.%d.%d.%d/%d", &a, &b, &c, &d, &bits); err != nil {
		panic(err)
	}
	mask := uint32(0)
	if bits > 0 {
		mask = ^uint32(0) << (32 - bits)
	}
	return ospf.Prefix{Network: a<<24 | b<<16 | c<<8 | d, Mask: mask, Metric: 20}
}
