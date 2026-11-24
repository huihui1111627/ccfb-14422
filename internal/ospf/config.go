package ospf

import (
	"fmt"
	"sort"
)

// AreaType models the special area kinds supported by this implementation.
type AreaType int

const (
	NormalArea AreaType = iota
	StubArea
	TotallyStubArea
	// NSSAArea is accepted by the configuration parser for completeness but
	// type-7 translation is not simulated.
	NSSAArea
)

func (t AreaType) String() string {
	switch t {
	case NormalArea:
		return "normal"
	case StubArea:
		return "stub"
	case TotallyStubArea:
		return "totally-stub"
	case NSSAArea:
		return "nssa"
	}
	return "?"
}

// Aggregate describes a summary range configured on an ABR for a source area.
type Aggregate struct {
	SourceArea uint32
	Network    uint32
	Mask       uint32
}

// AreaConfig holds the per-area policy knobs.
type AreaConfig struct {
	ID         uint32
	Type       AreaType
	Aggregates []Aggregate
}

type RouterConfig struct {
	ID          uint32
	Name        string
	IsASBR      bool
	Externals   []Prefix
	X, Y        float64
	PrimaryArea uint32
}

// LinkConfig is one physical point-to-point link.
type LinkConfig struct {
	ID      string
	A, B    uint32
	Area    uint32
	Cost    uint16
	MtuA    int
	MtuB    int
	DelayMS int
	Nominal int // nominal one-way propagation delay, ms
}

// VirtualLinkConfig is a virtual link (requirement 7): both endpoints must be
// area border routers and the transit area must be a normal area.
type VirtualLinkConfig struct {
	ID      string
	A, B    uint32
	Transit uint32
	Nominal int
	DelayMS int
}

// Topology is the immutable problem statement handed to every router.
type Topology struct {
	Routers []RouterConfig
	Links   []LinkConfig
	Virtual []VirtualLinkConfig
	Areas   []AreaConfig
}

// Topo is the indexed form of Topology with fast lookups.
type Topo struct {
	Routers map[uint32]*RouterConfig
	Links   map[string]*LinkConfig
	Areas   map[uint32]*AreaConfig
	// LinksByPair indexes physical links by unordered endpoint pair.
	LinksByPair map[[2]uint32][]*LinkConfig
	// VirtualByPair indexes virtual links by unordered endpoint pair.
	VirtualByPair map[[2]uint32]*VirtualLinkConfig
	// Virtual is the configured virtual link list in stable order.
	Virtual []VirtualLinkConfig
	// LinkAreas is the set of areas a link could belong to; for a point to
	// point link this is the configured area.
	Order []uint32
}

func pairKey(a, b uint32) [2]uint32 {
	if a < b {
		return [2]uint32{a, b}
	}
	return [2]uint32{b, a}
}

// BuildTopo validates and indexes a topology.
func BuildTopo(t *Topology) (*Topo, error) {
	top := &Topo{
		Routers:       map[uint32]*RouterConfig{},
		Links:         map[string]*LinkConfig{},
		Areas:         map[uint32]*AreaConfig{},
		LinksByPair:   map[[2]uint32][]*LinkConfig{},
		VirtualByPair: map[[2]uint32]*VirtualLinkConfig{},
	}
	top.Virtual = append(top.Virtual, t.Virtual...)
	for i := range t.Routers {
		r := &t.Routers[i]
		if r.ID == 0 {
			return nil, fmt.Errorf("router %q has zero ID", r.Name)
		}
		if _, dup := top.Routers[r.ID]; dup {
			return nil, fmt.Errorf("duplicate router ID %s", u32ip(r.ID))
		}
		top.Routers[r.ID] = r
	}
	for i := range t.Areas {
		a := &t.Areas[i]
		top.Areas[a.ID] = a
	}
	for i := range t.Links {
		l := &t.Links[i]
		if l.A == l.B {
			return nil, fmt.Errorf("link %s is a self loop", l.ID)
		}
		if _, ok := top.Routers[l.A]; !ok {
			return nil, fmt.Errorf("link %s unknown endpoint %s", l.ID, u32ip(l.A))
		}
		if _, ok := top.Routers[l.B]; !ok {
			return nil, fmt.Errorf("link %s unknown endpoint %s", l.ID, u32ip(l.B))
		}
		if _, ok := top.Areas[l.Area]; !ok {
			return nil, fmt.Errorf("link %s unknown area %s", l.ID, u32ip(l.Area))
		}
		if l.Cost == 0 {
			l.Cost = 10
		}
		if l.MtuA == 0 {
			l.MtuA = 1500
		}
		if l.MtuB == 0 {
			l.MtuB = 1500
		}
		if _, dup := top.Links[l.ID]; dup {
			return nil, fmt.Errorf("duplicate link id %s", l.ID)
		}
		top.Links[l.ID] = l
		k := pairKey(l.A, l.B)
		top.LinksByPair[k] = append(top.LinksByPair[k], l)
	}
	for i := range t.Virtual {
		v := &t.Virtual[i]
		if v.Nominal == 0 {
			v.Nominal = 20
		}
		ra, ok := top.Routers[v.A]
		if !ok {
			return nil, fmt.Errorf("virtual link %s unknown endpoint", v.ID)
		}
		rb, ok := top.Routers[v.B]
		if !ok {
			return nil, fmt.Errorf("virtual link %s unknown endpoint", v.ID)
		}
		if v.Transit == 0 || v.Transit == v.A || v.Transit == v.B {
			return nil, fmt.Errorf("virtual link %s bad transit area", v.ID)
		}
		if _, ok := top.Areas[v.Transit]; !ok {
			return nil, fmt.Errorf("virtual link %s unknown transit area", v.ID)
		}
		_ = ra
		_ = rb
		top.VirtualByPair[pairKey(v.A, v.B)] = v
	}
	// The maps hold pointers into t.Links, so the slice must never be
	// reordered after indexing. Callers that need a stable order sort the
	// IDs they obtain from map lookups.
	for id := range top.Routers {
		top.Order = append(top.Order, id)
	}
	sort.Slice(top.Order, func(i, j int) bool { return top.Order[i] < top.Order[j] })
	for k := range top.LinksByPair {
		ls := top.LinksByPair[k]
		sort.Slice(ls, func(i, j int) bool { return ls[i].ID < ls[j].ID })
	}
	return top, nil
}

// Adjacent reports the other endpoint of a link from the point of view of r.
func (l *LinkConfig) Adjacent(r uint32) uint32 {
	if l.A == r {
		return l.B
	}
	return l.A
}

// CostFor returns the cost of the link as seen from router r.
func (l *LinkConfig) CostFor(r uint32) uint16 {
	if l.A == r {
		return l.Cost
	}
	return l.Cost
}

// MTUFor returns the interface MTU at router r's end of the link.
func (l *LinkConfig) MTUFor(r uint32) int {
	if l.A == r {
		return l.MtuA
	}
	return l.MtuB
}

// LocalAddr is the interface address at router r's end of the link, encoded
// as a stable /31 style pair derived from the link endpoints.
func (l *LinkConfig) LocalAddr(r uint32) uint32 {
	if l.A == r {
		return 0x0a000000 | (l.A&0xffff)<<8 | (l.B & 0xff)
	}
	return 0x0a000000 | (l.B&0xffff)<<8 | (l.A & 0xff)
}

// Subnet is the /30 style transit subnet of the link.
func (l *LinkConfig) Subnet() uint32 {
	lo := l.A
	if l.B < lo {
		lo = l.B
	}
	return 0x0a000000 | (lo&0xffff)<<8&0xffffff00
}

// SubnetMask is a /30 mask for the link's transit subnet.
func (l *LinkConfig) SubnetMask() uint32 { return 0xffffff00 }

// LinkBetween returns the physical link connecting a and b, if any.
func (t *Topo) LinkBetween(a, b uint32) *LinkConfig {
	ls := t.LinksByPair[pairKey(a, b)]
	if len(ls) == 0 {
		return nil
	}
	return ls[0]
}

// AreaOfLink returns the area a physical link belongs to.
func (t *Topo) AreaOfLink(a, b uint32) uint32 {
	if l := t.LinkBetween(a, b); l != nil {
		return l.Area
	}
	return 0
}

// RouterAreas lists the areas a router participates in: the areas of all its
// physical links plus the backbone if it terminates a virtual link.
func (t *Topo) RouterAreas(r uint32) []uint32 {
	set := map[uint32]bool{}
	for _, l := range t.Links {
		if l.A == r || l.B == r {
			set[l.Area] = true
		}
	}
	for _, v := range t.Virtual {
		if v.A == r || v.B == r {
			set[0] = true
		}
	}
	var out []uint32
	for a := range set {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
