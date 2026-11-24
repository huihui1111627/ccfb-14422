package sim

import (
	"sort"

	"backhaul/internal/ospf"
)

// Snapshot is a point-in-time, read-only view of the simulation used by the
// verifier and the web page.
type Snapshot struct {
	At        int64
	Seed      int64
	Routers   []RouterView
	Links     []LinkView
	Areas     []AreaView
	Counters  Counters
	Audit     []ospf.AuditEvent
	LSACounts []*ospf.LSARec
}

// RouterView is one router's state for display.
type RouterView struct {
	ID     uint32
	Name   string
	X, Y   float64
	Areas  []uint32
	IsABR  bool
	IsASBR bool
	Nbrs   []ospf.NeighbourSnapshot
	Ifaces []ospf.InterfaceSnapshot
	Routes []RouteView
	DB     map[uint32][]LSAView
	SPF    map[uint32]string
}

// RouteView renders one routing table entry.
type RouteView struct {
	Prefix      string
	Cost        uint32
	NextHop     string
	Type        string
	Area        uint32
	Virtual     bool
	ViaBackbone bool
}

// LSAView renders one advertisement for the link state database panel.
type LSAView struct {
	Type     string
	TypeCode uint8
	LinkID   string
	AdvRtr   string
	Seq      string
	Age      uint16
	Checksum string
	Count    uint32
	Summary  string
}

// LinkView is the weather state of one physical link.
type LinkView struct {
	ID        string
	A, B      string
	Area      uint32
	Up        bool
	Condition string
	Cost      uint16
	BaseCost  uint16
	Loss      float64
	DelayMs   int64
	Events    int
	MtuA      int
	MtuB      int
	Virtual   bool
	Transit   uint32
}

// AreaView aggregates one area.
type AreaView struct {
	ID      uint32
	Type    string
	Routers int
	Links   int
	Stable  bool
}

// Counters is a summary of protocol volume.
type Counters struct {
	PacketsSent int
	PacketsLost int
	SentByType  map[string]int
	RecvByType  map[string]int
	SPFFull     int
	SPFIncr     int
	Dropped     map[string]int
	Transitions int
	LSAs        int
	Flooded     int
	Retrans     int
}

// Snapshot captures the current state.
func (s *Simulation) Snapshot() *Snapshot {
	snap := &Snapshot{At: s.NowTick, Seed: s.Seed}
	sent, lost, _ := s.Stats()
	snap.Counters = Counters{
		PacketsSent: sent, PacketsLost: lost,
		SentByType: map[string]int{}, RecvByType: map[string]int{},
		SPFFull: s.Metrics.SPFFull, SPFIncr: s.Metrics.SPFIncr,
		Dropped: map[string]int{}, Transitions: len(s.Audit.Transitions),
	}
	for k, v := range s.Metrics.Sent {
		snap.Counters.SentByType[ospf.PktTypeName(k)] = v
	}
	for k, v := range s.Metrics.Recv {
		snap.Counters.RecvByType[ospf.PktTypeName(k)] = v
	}
	for k, v := range s.Metrics.Dropped {
		snap.Counters.Dropped[k] = v
	}
	for _, rec := range s.Metrics.LSAs {
		snap.Counters.LSAs++
		snap.Counters.Flooded += rec.Flooded
		snap.Counters.Retrans += rec.Retransmitted
	}
	snap.LSACounts = s.Metrics.LSASorted()
	for _, id := range s.RouterIDs {
		r := s.Routers[id]
		rv := RouterView{
			ID: r.ID, Name: r.Name, X: r.X, Y: r.Y,
			Areas: r.Areas, IsABR: r.IsABR(), IsASBR: r.IsASBR,
			Nbrs: r.Neighbours(), Ifaces: r.InterfacesView(),
			DB: map[uint32][]LSAView{}, SPF: map[uint32]string{},
		}
		for _, rt := range r.Routes {
			rv.Routes = append(rv.Routes, RouteView{
				Prefix:      prefixString(rt.Prefix, rt.Mask),
				Cost:        rt.Cost,
				NextHop:     ipString(rt.NextHop),
				Type:        rt.Type.String(),
				Area:        rt.Area,
				Virtual:     rt.Virtual,
				ViaBackbone: rt.ViaBackbone,
			})
		}
		for _, area := range r.Areas {
			var lsas []LSAView
			for _, l := range r.AreaDB(area) {
				lsas = append(lsas, lsaView(l, s.NowTick))
			}
			rv.DB[area] = lsas
			rv.SPF[area] = r.LastSPF(area).String()
		}
		snap.Routers = append(snap.Routers, rv)
	}
	for _, l := range s.Topo.Links {
		ls := s.Links[l.ID]
		if ls == nil {
			continue
		}
		snap.Links = append(snap.Links, LinkView{
			ID: l.ID, A: ipString(l.A), B: ipString(l.B), Area: l.Area,
			Up: ls.Up, Condition: ls.Name(), Cost: ls.Cost, BaseCost: ls.BaseCost,
			Loss: ls.Loss, DelayMs: ls.DelayMs, Events: ls.Events,
			MtuA: l.MtuA, MtuB: l.MtuB,
		})
	}
	for _, v := range s.Topo.Virtual {
		up := s.virtualLinkUsable(v)
		cost := uint16(0)
		if r := s.Routers[v.A]; r != nil {
			if c, ok := r.TransitCostForArea(v.Transit); ok {
				cost = c
			}
		}
		snap.Links = append(snap.Links, LinkView{
			ID: v.ID, A: ipString(v.A), B: ipString(v.B), Area: 0,
			Up: up, Condition: "virtual", Cost: cost, BaseCost: 0,
			Virtual: true, Transit: v.Transit,
		})
	}
	sort.Slice(snap.Links, func(i, j int) bool { return snap.Links[i].ID < snap.Links[j].ID })
	areas := map[uint32]*AreaView{}
	for _, a := range s.Topo.Areas {
		if a == nil {
			continue
		}
		areas[a.ID] = &AreaView{ID: a.ID, Type: a.Type.String()}
	}
	for _, id := range s.RouterIDs {
		for _, a := range s.Routers[id].Areas {
			if av := areas[a]; av != nil {
				av.Routers++
			}
		}
	}
	for _, l := range s.Topo.Links {
		if av := areas[l.Area]; av != nil {
			av.Links++
		}
	}
	var areaIDs []uint32
	for id := range areas {
		areaIDs = append(areaIDs, id)
	}
	sort.Slice(areaIDs, func(i, j int) bool { return areaIDs[i] < areaIDs[j] })
	for _, id := range areaIDs {
		snap.Areas = append(snap.Areas, *areas[id])
	}
	snap.Audit = s.Audit.Recent(200)
	return snap
}

func ipString(v uint32) string {
	if v == 0 {
		return "0.0.0.0"
	}
	return ospf.IP(v)
}

func prefixString(net, mask uint32) string {
	n := ospf.PrefixName(net, mask)
	return n
}

func lsaView(l *ospf.LSA, now int64) LSAView {
	v := LSAView{
		Type: l.Type.String(), TypeCode: uint8(l.Type),
		LinkID: ospf.IP(l.ID), AdvRtr: ospf.IP(l.AdvRtr),
		Seq: fmtSeq(l.Seq), Age: l.CurrentAge(now),
		Checksum: fmtCks(l.Checksum), Count: l.Count,
	}
	switch l.Type {
	case ospf.LSARouter:
		var links []string
		for _, rl := range ospf.DecodeRouterLinks(l.Body) {
			kind := "p2p"
			switch rl.Type {
			case ospf.LinkStub:
				kind = "stub"
			case ospf.LinkVirtual:
				kind = "virt"
			}
			links = append(links, kind+" "+ospf.IP(rl.ID)+" cost "+itoa(int(rl.Metric)))
		}
		v.Summary = joinStr(links, "; ")
	case ospf.LSASummary, ospf.LSASummaryAS, ospf.LSAASExternal:
		var ps []string
		for _, p := range ospf.DecodePrefixes(l.Type, l.Body) {
			ps = append(ps, p.String()+" cost "+itoa(int(p.Metric)))
		}
		v.Summary = joinStr(ps, "; ")
	}
	return v
}

func fmtSeq(v uint32) string {
	const hex = "0123456789abcdef"
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = hex[v&0xf]
		v >>= 4
	}
	return string(b)
}

func fmtCks(v uint16) string {
	const hex = "0123456789abcdef"
	return string([]byte{hex[(v>>12)&0xf], hex[(v>>8)&0xf], hex[(v>>4)&0xf], hex[v&0xf]})
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	if v < 0 {
		return "-" + itoa(-v)
	}
	var b [12]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func joinStr(parts []string, sep string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += sep
		}
		out += p
	}
	return out
}
