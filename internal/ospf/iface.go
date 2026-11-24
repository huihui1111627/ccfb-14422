package ospf

import (
	"fmt"
)

// Receive is the single entry point through which the link layer hands a
// decoded packet to this router. It validates the packet against the
// interface it arrived on and dispatches to the per-type handler.
func (r *Router) Receive(linkID string, pkt *Packet, now int64) {
	if pkt == nil {
		return
	}
	// Resolve the interface by link ID. Virtual links arrive as "vl:<name>";
	// the name encodes the transit area and the peer.
	var i *Interface
	if len(linkID) > 3 && linkID[:3] == "vl:" {
		// A virtual link is identified by its peer, not by the sender's
		// interface name, because the two ends name the link from their own
		// point of view.
		for _, trans := range sortedAreaKeys(r.VirInterfaces) {
			if cand := r.VirInterfaces[trans][pkt.Src]; cand != nil {
				i = cand
				break
			}
		}
	} else {
		i = r.Interfaces[linkID]
	}
	if i == nil {
		r.Metrics.Drop("no-interface")
		return
	}
	if i.State == IfDown {
		r.Metrics.Drop("if-down")
		return
	}
	// Hellos are the only packets accepted from a neighbour in Down state.
	from := pkt.Src
	_, known := i.Nbrs[from]
	isHello := pkt.Type == PktHello
	if !known && !isHello {
		r.Metrics.Drop("unknown-nbr")
		return
	}
	// A packet for another area's interface is a misconfiguration.
	if i.Area != pkt.SrcArea && !i.Virtual {
		r.Metrics.Drop("area-mismatch")
		return
	}
	r.Metrics.Recv[pkt.Type]++
	switch pkt.Type {
	case PktHello:
		r.handleHello(i, from, pkt.Body, now)
	case PktDD:
		r.handleDD(i, from, pkt.Body, now)
	case PktLSR:
		r.handleLSR(i, from, pkt.Body, now)
	case PktLSU:
		r.handleLSU(i, from, pkt.Body, now)
	case PktLSAck:
		r.handleLSAck(i, from, pkt.Body, now)
	default:
		r.Metrics.Drop("bad-type")
	}
}

// SetInterfaceDown forces an interface down (weather or admin).
func (r *Router) SetInterfaceDown(name string, now int64) {
	if i := r.Interfaces[name]; i != nil && i.State != IfDown {
		r.interfaceDown(name, now)
	}
	for _, trans := range sortedAreaKeys(r.VirInterfaces) {
		if i := r.VirInterfaces[trans][trans]; i != nil {
			_ = i
		}
	}
}

// SetInterfaceUp forces an interface up.
func (r *Router) SetInterfaceUp(name string, now int64) {
	if i := r.Interfaces[name]; i != nil && i.State == IfDown {
		r.interfaceUp(name, now)
	}
}

// Shutdown stops the protocol on this router: every interface goes down and
// every neighbour is killed.
func (r *Router) Shutdown(now int64) {
	for _, name := range r.ifOrder {
		r.interfaceDown(name, now)
	}
	r.Audit.Event(now, EvArea, r.ID, 0, "router shutdown")
}

// NeighbourSnapshot is the page-facing view of one adjacency.
type NeighbourSnapshot struct {
	RouterID        uint32
	State           string
	StateCode       NbrState
	Interface       string
	Area            uint32
	MtuLocal        int
	MtuRemote       int
	MtuDisagreement bool
	StuckReason     string
	Since           int64
	HellosRecv      int
	LSRetransmit    int
	LSRequested     int
	Master          bool
	Options         uint8
}

// Neighbours lists every adjacency of this router in a stable order.
func (r *Router) Neighbours() []NeighbourSnapshot {
	var out []NeighbourSnapshot
	add := func(i *Interface) {
		for _, peer := range sortedNbrKeys(i.Nbrs) {
			n := i.Nbrs[peer]
			snap := NeighbourSnapshot{
				RouterID:        n.RouterID,
				State:           n.State.String(),
				StateCode:       n.State,
				Interface:       i.Name,
				Area:            i.Area,
				MtuLocal:        i.Mtu,
				MtuRemote:       n.MtuRemote,
				MtuDisagreement: n.MtuDisagreement,
				Since:           n.StateSince,
				HellosRecv:      n.HellosRecv,
				LSRetransmit:    len(n.LSRetransmit),
				LSRequested:     len(n.LSRequests),
				Master:          n.Master,
				Options:         n.Options,
			}
			if n.MtuDisagreement {
				snap.StuckReason = fmt.Sprintf("MTU mismatch: local %d, remote %d", n.MtuLocal, n.MtuRemote)
			}
			out = append(out, snap)
		}
	}
	for _, name := range r.ifOrder {
		add(r.Interfaces[name])
	}
	for _, trans := range sortedAreaKeys(r.VirInterfaces) {
		for _, peer := range sortedPeerKeys(r.VirInterfaces[trans]) {
			add(r.VirInterfaces[trans][peer])
		}
	}
	return out
}

// InterfaceSnapshot is the page-facing view of one interface.
type InterfaceSnapshot struct {
	Name    string
	Area    uint32
	State   string
	Cost    uint16
	Mtu     int
	Peer    uint32
	Virtual bool
	Transit uint32
	Nbrs    int
}

func (r *Router) InterfacesView() []InterfaceSnapshot {
	var out []InterfaceSnapshot
	for _, name := range r.ifOrder {
		i := r.Interfaces[name]
		out = append(out, InterfaceSnapshot{
			Name: i.Name, Area: i.Area, State: i.State.String(), Cost: i.Cost,
			Mtu: i.Mtu, Peer: i.Peer, Nbrs: len(i.Nbrs),
		})
	}
	for _, trans := range sortedAreaKeys(r.VirInterfaces) {
		for _, peer := range sortedPeerKeys(r.VirInterfaces[trans]) {
			i := r.VirInterfaces[trans][peer]
			out = append(out, InterfaceSnapshot{
				Name: i.Name, Area: i.Area, State: i.State.String(), Cost: i.Cost,
				Mtu: i.Mtu, Peer: i.Peer, Virtual: true, Transit: i.Transit, Nbrs: len(i.Nbrs),
			})
		}
	}
	return out
}

// HasInterface reports whether the router has an interface bound to a link.
func (r *Router) HasInterface(name string) bool {
	_, ok := r.Interfaces[name]
	return ok
}
