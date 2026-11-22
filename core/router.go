package core

import (
	"fmt"
	"sort"
)

// RouteType classifies routing table entries.
type RouteType int

const (
	RouteIntra RouteType = iota
	RouteInter
	RouteExternal
)

func (t RouteType) String() string {
	return []string{"intra-area", "inter-area", "external"}[t]
}

// Route is one routing table entry.
type Route struct {
	Prefix   Prefix
	Type     RouteType
	Cost     int        // total cost (external: type-2 metric)
	Cost2    int        // external: internal cost to ASBR (tiebreak)
	NextHops []RouterID // sorted first-hop neighbor ids (empty for self)
	Adv      RouterID   // advertising ABR/ASBR (inter/external)
}

func (r *Route) String() string {
	nh := make([]string, len(r.NextHops))
	for i, n := range r.NextHops {
		nh[i] = IDStr(n)
	}
	return fmt.Sprintf("%s via %v cost %d (%s)", r.Prefix, nh, r.Cost, r.Type)
}

// LinkChange describes one directed edge change for incremental SPF.
type LinkChange struct {
	From, To RouterID
	OldCost  int // -1 if the edge did not exist
	NewCost  int // -1 if the edge is gone
}

// Router is one OSPF routing process.
type Router struct {
	ID RouterID
	W  *World

	Ifaces  []*Interface
	VLNbrs  []*Neighbor // virtual link neighbors
	AreaSet map[AreaID]bool

	LSDB  map[AreaID]map[LSAKey]*LSA // router + summary LSAs per area
	ExtDB map[LSAKey]*LSA            // AS-external LSAs
	Self  map[selfKey]*LSA           // self-originated (any type)

	RIB map[Prefix]*Route

	// per-area SPF state
	SPTs         map[AreaID]*SPT
	IntraRoutes  map[AreaID]map[Prefix]*Route
	spfScheduled map[AreaID]bool
	linkChanges  map[AreaID][]LinkChange // pending single-link changes for iSPF
	fullSPFOnly  map[AreaID]bool

	ASBR    bool
	Statics []ExternalLSABody // configured external routes to originate

	areaSummaries map[AreaID]map[Prefix]*LSA // self-originated summaries per area
	refreshTimers map[selfKey]*Event
	seqHist       map[selfKey]uint32 // monotonic sequence history per LSA key
}

// NewRouter creates a router in the world.
func (w *World) NewRouter(id RouterID) *Router {
	r := &Router{
		ID:            id,
		W:             w,
		AreaSet:       make(map[AreaID]bool),
		LSDB:          make(map[AreaID]map[LSAKey]*LSA),
		ExtDB:         make(map[LSAKey]*LSA),
		Self:          make(map[selfKey]*LSA),
		RIB:           make(map[Prefix]*Route),
		SPTs:          make(map[AreaID]*SPT),
		IntraRoutes:   make(map[AreaID]map[Prefix]*Route),
		spfScheduled:  make(map[AreaID]bool),
		linkChanges:   make(map[AreaID][]LinkChange),
		fullSPFOnly:   make(map[AreaID]bool),
		areaSummaries: make(map[AreaID]map[Prefix]*LSA),
	}
	w.Routers[id] = r
	return r
}

// Loopback returns the router's loopback prefix (its router id as /32).
func (r *Router) Loopback() Prefix { return Prefix{Addr: uint32(r.ID), Len: 32} }

// AddInterface attaches the router to a link in an area.
func (w *World) AddInterface(r *Router, link *Link, area AreaID, mtu int) *Interface {
	ifc := &Interface{ID: len(r.Ifaces), R: r, Link: link, Area: area, MTU: mtu}
	r.Ifaces = append(r.Ifaces, ifc)
	r.AreaSet[area] = true
	if r.LSDB[area] == nil {
		r.LSDB[area] = make(map[LSAKey]*LSA)
	}
	if w.Areas[area] == nil {
		w.Areas[area] = &AreaConf{}
	}
	return ifc
}

// AddLink creates a point-to-point link between two routers.
func (w *World) AddLink(a, b *Router, area AreaID, cost int, delay int64, mtuA, mtuB int) *Link {
	l := &Link{ID: len(w.Links), Cost: cost, Delay: delay, Up: true}
	l.A = w.AddInterface(a, l, area, mtuA)
	l.B = w.AddInterface(b, l, area, mtuB)
	w.Links = append(w.Links, l)
	return l
}

// SortedAreas returns the router's areas in order.
func (r *Router) SortedAreas() []AreaID {
	as := make([]AreaID, 0, len(r.AreaSet))
	for a := range r.AreaSet {
		as = append(as, a)
	}
	sort.Slice(as, func(i, j int) bool { return as[i] < as[j] })
	return as
}

// AllNeighbors returns all neighbors (interface + virtual link), sorted.
func (r *Router) AllNeighbors() []*Neighbor {
	var ns []*Neighbor
	for _, ifc := range r.Ifaces {
		if ifc.Nbr != nil {
			ns = append(ns, ifc.Nbr)
		}
	}
	ns = append(ns, r.VLNbrs...)
	sort.Slice(ns, func(i, j int) bool { return ns[i].RtrID < ns[j].RtrID })
	return ns
}

// IsABR reports whether the router attaches to the backbone and another area.
func (r *Router) IsABR() bool {
	return r.AreaSet[Backbone] && len(r.AreaSet) > 1
}

// lookupLSA finds an LSA instance in the appropriate database.
func (r *Router) lookupLSA(area AreaID, k LSAKey) *LSA {
	if k.Type == LSAExternal {
		return r.ExtDB[k]
	}
	if db := r.LSDB[area]; db != nil {
		return db[k]
	}
	return nil
}

// --- LSA origination -----------------------------------------------------

const seqStart uint32 = 0x80000001

// selfKey scopes an LSA key by its flooding area: the same LSAKey (e.g. a
// router LSA) exists once per area and must be tracked independently.
type selfKey struct {
	area AreaID
	key  LSAKey
}

func sk(area AreaID, k LSAKey) selfKey {
	if k.Type == LSAExternal {
		area = Backbone // externals have domain-wide scope, single instance
	}
	return selfKey{area, k}
}

// nextSeq returns the next sequence number for a self-originated LSA. The
// sequence space is monotonic per key for the lifetime of the router: even
// after an LSA is flushed and later re-originated, the new instance must win
// the freshness comparison against the flushed copies still circulating.
func (r *Router) nextSeq(area AreaID, k LSAKey) uint32 {
	sk := sk(area, k)
	s := seqStart
	if r.seqHist[sk] >= s {
		s = r.seqHist[sk] + 1
	}
	if old := r.Self[sk]; old != nil && old.Seq >= s {
		s = old.Seq + 1
	}
	if r.seqHist == nil {
		r.seqHist = make(map[selfKey]uint32)
	}
	r.seqHist[sk] = s
	return s
}

// originate installs and floods a fresh self-originated LSA.
func (r *Router) originate(area AreaID, k LSAKey, body interface{}) {
	l := &LSA{Key: k, Seq: r.nextSeq(area, k), Body: body, Self: true}
	l.Cksum = l.checksum()
	r.installLSA(area, l, nil)
	sk := sk(area, k)
	r.Self[sk] = l
	// schedule periodic refresh
	w := r.W
	areaCopy, keyCopy := area, k
	if r.refreshTimers == nil {
		r.refreshTimers = make(map[selfKey]*Event)
	}
	if old := r.refreshTimers[sk]; old != nil {
		old.Cancel()
	}
	r.refreshTimers[sk] = w.Schedule(w.Cfg.RefreshTime, true, "refresh", func() {
		if cur := r.Self[sk]; cur != nil {
			r.originate(areaCopy, keyCopy, cur.Body)
		}
	})
}

// flushLSA prematurely ages a self-originated LSA out of the domain.
func (r *Router) flushLSA(area AreaID, k LSAKey) {
	sk := sk(area, k)
	old := r.Self[sk]
	if old == nil {
		return
	}
	delete(r.Self, sk)
	if t := r.refreshTimers[sk]; t != nil {
		t.Cancel()
		delete(r.refreshTimers, sk)
	}
	l := &LSA{Key: k, Seq: r.nextSeq(area, k), Body: old.Body, Self: true, BaseAge: uint16(r.W.Cfg.MaxAge)}
	l.Cksum = old.Cksum
	r.installLSA(area, l, nil)
}

// originateRouterLSA rebuilds the router's Router-LSA for one area.
func (r *Router) originateRouterLSA(area AreaID) {
	body := &RouterLSABody{}
	if r.IsABR() {
		body.Flags |= FlagB
	}
	if r.ASBR {
		body.Flags |= FlagE
	}
	// own loopback as a stub network
	body.Links = append(body.Links, RouterLink{Type: LinkStub, ID: uint32(r.ID), Data: 0xffffffff, Metric: 0})
	for _, ifc := range r.Ifaces {
		if ifc.Area != area || !ifc.Up() {
			continue
		}
		if ifc.Nbr != nil && ifc.Nbr.State == NbrFull {
			body.Links = append(body.Links, RouterLink{
				Type:   LinkP2P,
				ID:     uint32(ifc.Nbr.RtrID),
				Metric: ifc.Link.Cost,
			})
		}
	}
	if area == Backbone {
		for _, n := range r.VLNbrs {
			if n.State == NbrFull {
				body.Flags |= FlagV
				body.Links = append(body.Links, RouterLink{
					Type:   LinkVirtual,
					ID:     uint32(n.RtrID),
					Metric: n.VLCost,
				})
			}
		}
	}
	k := LSAKey{Type: LSARouter, LSID: uint32(r.ID), Adv: r.ID}
	r.originate(area, k, body)
}

// --- LSA install / flooding ----------------------------------------------

// installLSA processes an LSA (received or self-originated): installs it if
// newer, floods it, schedules aging, and triggers SPF.
func (r *Router) installLSA(area AreaID, l *LSA, from *Neighbor) bool {
	w := r.W
	l.InstalledAt = w.Now
	var db map[LSAKey]*LSA
	if l.Key.Type == LSAExternal {
		db = r.ExtDB
	} else {
		db = r.LSDB[area]
		if db == nil {
			db = make(map[LSAKey]*LSA)
			r.LSDB[area] = db
		}
	}
	existing := db[l.Key]
	if existing != nil && !l.NewerThan(existing, w.Now, w.Cfg.MaxAgeDiff, w.Cfg.MaxAge) {
		return false
	}
	db[l.Key] = l
	if l.Key.Type == LSARouter {
		r.diffRouterLSA(area, existing, l)
	} else {
		r.scheduleSPF(area)
	}
	r.floodLSA(area, l, from)
	// schedule natural MaxAge transition
	if l.Age(w.Now) < w.Cfg.MaxAge {
		key := l.Key
		areaC := area
		w.Schedule(w.Cfg.MaxAge-l.Age(w.Now), true, "maxage", func() {
			cur := r.lookupLSA(areaC, key)
			if cur != nil && cur.Age(r.W.Now) < r.W.Cfg.MaxAge {
				return
			}
			if cur != nil && int64(cur.BaseAge) < r.W.Cfg.MaxAge {
				// aged out naturally: reflood as MaxAge; the tombstone stays
				// in the database (see below)
				cur.BaseAge = uint16(r.W.Cfg.MaxAge)
				r.floodLSA(areaC, cur, nil)
				r.scheduleSPF(areaC)
			}
		})
	}
	// A MaxAge LSA is kept in the database as a tombstone until it is
	// superseded by a newer instance. It is never removed on a timer:
	// a removed tombstone lets a stale younger copy resurrect when it
	// re-floods in from a partition that never saw the flush. Tombstones do
	// not take part in route computation (spf.go skips them), but they are
	// advertised in DD exchanges so stale copies are purged on contact.
	return true
}

// hasExchangingNeighbors reports whether any neighbor is mid-database-sync.
func (r *Router) hasExchangingNeighbors() bool {
	for _, n := range r.AllNeighbors() {
		if n.State == NbrExchange || n.State == NbrLoading {
			return true
		}
	}
	return false
}

// removeLSA deletes an LSA from the local database and triggers SPF.
func (r *Router) removeLSA(area AreaID, k LSAKey) {
	var db map[LSAKey]*LSA
	if k.Type == LSAExternal {
		db = r.ExtDB
	} else {
		db = r.LSDB[area]
	}
	old := db[k]
	if old == nil {
		return
	}
	delete(db, k)
	if k.Type == LSARouter {
		r.diffRouterLSA(area, old, nil)
	} else {
		r.scheduleSPF(area)
	}
}

// diffRouterLSA detects single-link changes between two versions of a
// Router-LSA so that SPF can run incrementally.
func (r *Router) diffRouterLSA(area AreaID, old, new *LSA) {
	if old == nil || new == nil || old.Key.Type != LSARouter || new.Key.Type != LSARouter {
		r.fullSPFOnly[area] = true
		r.scheduleSPF(area)
		return
	}
	ob, nb := old.RouterBody(), new.RouterBody()
	om := make(map[RouterID]int)
	for _, lk := range ob.Links {
		if lk.Type == LinkP2P || lk.Type == LinkVirtual {
			om[RouterID(lk.ID)] = lk.Metric
		}
	}
	nm := make(map[RouterID]int)
	for _, lk := range nb.Links {
		if lk.Type == LinkP2P || lk.Type == LinkVirtual {
			nm[RouterID(lk.ID)] = lk.Metric
		}
	}
	changes := 0
	for id, oc := range om {
		nc, ok := nm[id]
		if !ok {
			nc = -1
		}
		if oc != nc {
			r.linkChanges[area] = append(r.linkChanges[area], LinkChange{From: old.Key.Adv, To: id, OldCost: oc, NewCost: nc})
			changes++
		}
	}
	for id, nc := range nm {
		if _, ok := om[id]; !ok {
			r.linkChanges[area] = append(r.linkChanges[area], LinkChange{From: old.Key.Adv, To: id, OldCost: -1, NewCost: nc})
			changes++
		}
	}
	if changes != 1 {
		r.fullSPFOnly[area] = true
	}
	r.scheduleSPF(area)
}

// floodLSA sends an LSA to all eligible neighbors except the one it came from.
func (r *Router) floodLSA(area AreaID, l *LSA, except *Neighbor) {
	for _, n := range r.AllNeighbors() {
		if n == except || n.State < NbrExchange {
			continue
		}
		if l.Key.Type == LSAExternal {
			ac := r.W.Areas[n.Area()]
			if ac != nil && ac.Stub {
				continue // externals never enter stub areas
			}
		} else if n.Area() != area {
			continue
		}
		r.sendLSU(n, []*LSA{l})
	}
}

// sendLSU transmits LSAs to a neighbor and tracks them for retransmission.
func (r *Router) sendLSU(n *Neighbor, lsas []*LSA) { r.sendLSUP(n, lsas, false) }

func (r *Router) sendLSUP(n *Neighbor, lsas []*LSA, periodic bool) {
	// send stamped copies: the receiver will install its own instance, and
	// the age accumulated so far must travel with the LSA
	stamped := make([]*LSA, 0, len(lsas))
	for _, l := range lsas {
		cp := *l
		age := l.Age(r.W.Now)
		if age > r.W.Cfg.MaxAge {
			age = r.W.Cfg.MaxAge
		}
		cp.BaseAge = uint16(age)
		stamped = append(stamped, &cp)
	}
	pkt := &Packet{Type: PktLSU, LSAs: stamped}
	n.sendP(pkt, periodic)
	if n.RetxList == nil {
		n.RetxList = make(map[LSAKey]*LSA)
	}
	for _, l := range stamped {
		n.RetxList[l.Key] = l
	}
	r.armLSURetx(n)
}

// handleLSU processes received Link State Update packets.
func (r *Router) handleLSU(n *Neighbor, pkt *Packet) {
	if n == nil || n.State < NbrExchange {
		return
	}
	w := r.W
	area := n.Area()
	var acks []*LSA
	for _, l := range pkt.LSAs {
		if l.Key.Type == LSAExternal {
			ac := w.Areas[area]
			if ac != nil && ac.Stub {
				continue
			}
		}
		// any LSA received from this neighbor during Loading satisfies the
		// matching request-list entry, regardless of instance freshness
		r.satisfyRequest(n, l.Key)
		// implied acknowledgment: the neighbor obviously holds a copy at
		// least as new as what it just sent us, so any same-or-older
		// instance on its retransmission list can be dropped
		if rtx, ok := n.RetxList[l.Key]; ok {
			if !rtx.NewerThan(l, w.Now, w.Cfg.MaxAgeDiff, w.Cfg.MaxAge) {
				delete(n.RetxList, l.Key)
			}
		}
		existing := r.lookupLSA(area, l.Key)
		// a MaxAge LSA we do not have is acknowledged but not installed when
		// no database exchange is in progress (RFC 2328 section 13, step 6)
		if existing == nil && l.Age(w.Now) >= w.Cfg.MaxAge && !r.hasExchangingNeighbors() {
			acks = append(acks, headerOf(l, w.Now))
			continue
		}
		// self-originated LSA coming back from the network that would beat
		// our current instance (higher seq, or MaxAge): advance our sequence
		// space past it and re-originate instead of installing it
		// (RFC 2328 sections 13.4 and 14.1)
		if l.Key.Adv == r.ID {
			sk := sk(area, l.Key)
			if self := r.Self[sk]; self != nil {
				if l.NewerThan(self, w.Now, w.Cfg.MaxAgeDiff, w.Cfg.MaxAge) {
					r.seqHist[sk] = l.Seq
					r.originate(area, l.Key, self.Body)
					continue
				}
			} else if l.Age(w.Now) < w.Cfg.MaxAge &&
				(existing == nil || l.NewerThan(existing, w.Now, w.Cfg.MaxAgeDiff, w.Cfg.MaxAge)) {
				// we no longer originate this LSA but a live copy is still
				// circulating: purge it with a higher-sequence MaxAge instance
				purge := &LSA{Key: l.Key, Seq: r.nextSeq(area, l.Key), Body: l.Body,
					BaseAge: uint16(w.Cfg.MaxAge)}
				purge.Cksum = purge.checksum()
				r.installLSA(area, purge, nil)
				continue
			}
		}
		switch {
		case existing == nil || l.NewerThan(existing, w.Now, w.Cfg.MaxAgeDiff, w.Cfg.MaxAge):
			r.installLSA(area, l, n)
			acks = append(acks, headerOf(l, w.Now))
		case existing.NewerThan(l, w.Now, w.Cfg.MaxAgeDiff, w.Cfg.MaxAge):
			// neighbor has an older copy: send our newer instance back
			r.sendLSU(n, []*LSA{existing})
		default:
			acks = append(acks, headerOf(l, w.Now))
		}
	}
	if len(acks) > 0 {
		n.send(&Packet{Type: PktLSAck, LSAs: acks})
	}
}

// satisfyRequest removes a key from the neighbor request list during Loading.
func (r *Router) satisfyRequest(n *Neighbor, k LSAKey) {
	if n.State != NbrLoading {
		return
	}
	for i, rk := range n.ReqList {
		if rk == k {
			n.ReqList = append(n.ReqList[:i], n.ReqList[i+1:]...)
			break
		}
	}
	if len(n.ReqList) == 0 {
		if n.lsrRetx != nil {
			n.lsrRetx.Cancel()
			n.lsrRetx = nil
		}
		r.nbrFull(n)
	}
}
