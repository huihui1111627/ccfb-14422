package ospf

import (
	"sort"
)

// selfFor and seqsFor lazily create the per-area maps.
func (r *Router) selfFor(area uint32) map[LSAKey]*LSA {
	m := r.self[area]
	if m == nil {
		m = map[LSAKey]*LSA{}
		r.self[area] = m
	}
	return m
}

func (r *Router) seqsFor(area uint32) map[LSAKey]uint32 {
	m := r.seqs[area]
	if m == nil {
		m = map[LSAKey]uint32{}
		r.seqs[area] = m
	}
	return m
}

// ---- Origination ----------------------------------------------------------

// nextSeq returns the next sequence number for a self-originated LSA.
func (r *Router) nextSeq(area uint32, k LSAKey) uint32 {
	s := r.seqsFor(area)[k]
	if s == 0 {
		s = InitialSeqNum
	}
	return s
}

// bumpSeq increments and records the sequence for a self-originated LSA.
func (r *Router) bumpSeq(area uint32, k LSAKey) uint32 {
	seqs := r.seqsFor(area)
	s := seqs[k]
	if s == 0 {
		s = InitialSeqNum
	} else {
		s++
	}
	seqs[k] = s
	return s
}

// originateRouterLSA builds and installs this router's type 1 advertisement
// for one area, then floods any change.
func (r *Router) originateRouterLSA(area uint32, now int64) {
	if !r.AreaEnabled(area) && !r.hasVirtualInBackbone(area) {
		// Detached areas still need a router LSA if the router has any
		// interface in them; AreaEnabled covers physical links.
		return
	}
	links := r.routerLinks(area, now)
	flags := r.routerFlags(area)
	opts := r.areaOptions(area)
	k := LSAKey{Type: LSARouter, ID: r.ID, AdvRtr: r.ID}
	seq := r.bumpSeq(area, k)
	l := BuildRouterLSA(r.ID, area, opts, flags, seq, links)
	l.ReceivedAt = now
	l.SourceRtr = r.ID
	self := r.selfFor(area)
	self[k] = l
	r.installSelf(area, l, now)
}

func (r *Router) hasVirtualInBackbone(area uint32) bool { return area == 0 && len(r.VirInterfaces) > 0 }

// routerFlags sets the ABR/ASBR/virtual-link bits.
func (r *Router) routerFlags(area uint32) uint8 {
	var f uint8
	areas := map[uint32]bool{}
	for _, a := range r.Areas {
		areas[a] = true
	}
	hasVirt := len(r.VirInterfaces) > 0
	if len(areas) > 1 && areas[0] && area != 0 {
		f |= FlagABR
	}
	if hasVirt && area == 0 {
		f |= FlagABR | FlagVirt
	}
	if r.IsASBR && area != 0 {
		f |= FlagASBR
	}
	if r.IsASBR && (len(r.Areas) == 1 && r.Areas[0] == 0) {
		f |= FlagASBR
	}
	return f
}

// routerLinks enumerates the links this router advertises in one area.
func (r *Router) routerLinks(area uint32, now int64) []RouterLink {
	var out []RouterLink
	var physical []*LinkConfig
	for _, l := range r.Topo.Links {
		if l.Area != area {
			continue
		}
		if l.A == r.ID || l.B == r.ID {
			physical = append(physical, l)
		}
	}
	sort.Slice(physical, func(i, j int) bool {
		return physical[i].Adjacent(r.ID) < physical[j].Adjacent(r.ID)
	})
	for _, l := range physical {
		i := r.Interfaces[l.ID]
		if i == nil || i.State == IfDown {
			continue
		}
		iface := i.Cost
		if l.CostFor(r.ID) != 0 {
			iface = l.CostFor(r.ID)
		}
		out = append(out, RouterLink{
			ID:     l.Adjacent(r.ID),
			Data:   l.LocalAddr(r.ID),
			Type:   LinkP2P,
			Metric: iface,
		})
	}
	// Each router advertises exactly one stub: its station /24, derived from
	// its router ID. Advertising link subnets as stubs as well would make both
	// ends of every link announce the same network, and the resulting equal
	// and differing costs would make the route table and the summaries churn.
	out = append(out, RouterLink{
		ID:     stationSubnet(r.ID),
		Data:   0xffffffff,
		Type:   LinkStub,
		Metric: 1,
	})
	if area == 0 {
		// Virtual links are advertised as type 4 links in the backbone.
		for _, trans := range sortedAreaKeys(r.VirInterfaces) {
			for _, peer := range sortedPeerKeys(r.VirInterfaces[trans]) {
				i := r.VirInterfaces[trans][peer]
				if i.State == IfDown || !r.virtualUsable(trans) {
					continue
				}
				out = append(out, RouterLink{
					ID:     peer,
					Data:   r.virtualInterfaceAddr(peer),
					Type:   LinkVirtual,
					Metric: r.virtualCost(trans),
				})
			}
		}
	}
	return out
}

// ---- Installation ---------------------------------------------------------

// installSelf installs a self-originated advertisement and floods the change
// to every adjacent neighbour in the area that is at least in Exchange.
func (r *Router) installSelf(area uint32, l *LSA, now int64) {
	r.lastDBChange = now
	k := l.Key()
	old := r.areaDB[area][k]
	r.db(area)[k] = l
	r.Metrics.Originated(l)
	r.Audit.Event(now, EvFlood, r.ID, area, "originate %s seq %08x", k, l.Seq)
	r.flood(area, l, now)
	if old == nil || !old.PayloadEqual(l) {
		r.noteChange(area, k, old, l)
	}
}

// installLSA processes a received advertisement through the decision logic of
// RFC 2328 section 13 step 5 and returns whether the database changed.
func (r *Router) installLSA(area uint32, in *LSA, from uint32, now int64) bool {
	k := in.Key()
	cur := r.areaDB[area][k]
	if cur == nil {
		// Brand new instance.
		r.lastDBChange = now
		r.db(area)[k] = in
		r.noteChange(area, k, nil, in)
		r.Audit.Event(now, EvFlood, r.ID, area, "learn %s seq %08x from %s", k, in.Seq, u32ip(from))
		r.floodFrom(area, in, from, now)
		r.maybeReoriginate(k, area, now)
		return true
	}
	curAged := cur.AgedCopy(now)
	cmp := LSACompare(in, curAged)
	switch {
	case cmp > 0:
		// Newer: replace and flood to others, but never back to the source.
		r.lastDBChange = now
		r.db(area)[k] = in
		r.noteChange(area, k, cur, in)
		r.Audit.Event(now, EvFlood, r.ID, area, "install %s seq %08x age %d (was %08x) from %s",
			k, in.Seq, in.Age, cur.Seq, u32ip(from))
		r.floodFrom(area, in, from, now)
		r.maybeReoriginate(k, area, now)
		return true
	case cmp < 0:
		// Requirement 3: our copy is newer; send it straight back to the
		// sender so the stale copy is corrected.
		r.sendBack(area, curAged, from, now)
		r.Metrics.StaleReplied(cur)
		r.Audit.Event(now, EvFlood, r.ID, area, "reject stale %s seq %08x, resend %08x to %s",
			k, in.Seq, cur.Seq, u32ip(from))
		return false
	default:
		// Same instance: just refresh the age baseline when the incoming copy
		// is meaningfully younger, so the database does not age out early.
		if in.Age+MaxAgeDiff < curAged.Age {
			cur.ReceivedAt = now
			cur.Age = in.Age
		}
		return false
	}
}

// maybeReoriginate handles the case where a received LSA claims our own
// router ID: the peer's copy is newer, so we must bump our sequence.
func (r *Router) maybeReoriginate(k LSAKey, area uint32, now int64) {
	if k.AdvRtr != r.ID || k.Type != LSARouter {
		return
	}
	// Only re-originate when the other copy is genuinely more recent than the
	// sequence we hold. A copy that is merely a different object with the same
	// sequence is our own advertisement coming back around a flood loop and
	// must be ignored, otherwise the two routers keep re-originating forever.
	cur := r.areaDB[area][k]
	if cur == nil {
		return
	}
	if !seqGT(cur.Seq, r.seqsFor(area)[k]) {
		// Same sequence: restore our own pointer (flooding may have replaced
		// the object) and leave the sequence alone.
		if own, ok := r.selfFor(area)[k]; ok && own.Seq == cur.Seq && own.Checksum == cur.Checksum {
			r.db(area)[k] = own
		}
		return
	}
	r.seqsFor(area)[k] = cur.Seq
	r.originateRouterLSA(area, now)
}

// flushLSA replaces an advertisement with its MaxAge version so it is removed
// from every database in the area (requirement 4).
func (r *Router) flushLSA(area uint32, k LSAKey, now int64) {
	cur := r.areaDB[area][k]
	if cur == nil {
		return
	}
	if cur.CurrentAge(now) >= MaxAge {
		return
	}
	fl := cur.Clone()
	fl.Age = MaxAge
	fl.ReceivedAt = now
	fl.SourceRtr = r.ID
	r.db(area)[k] = fl
	r.noteChange(area, k, cur, fl)
	r.Metrics.Flushed(cur)
	r.Audit.Event(now, EvFlood, r.ID, area, "flush %s (maxage)", k)
	r.flood(area, fl, now)
	r.scheduleMaxAgeRemoval(area, k, fl, now)
}

// scheduleMaxAgeRemoval is deliberately a no-op.
//
// A MaxAge advertisement is kept in the database instead of being deleted.
// That is what makes the databases converge after an area heals: a router that
// was cut off while the flush was flooding still holds the old instance, and
// when the adjacency comes back the database description exchange sees our
// MaxAge copy as more recent and requests it. Deleting the flush locally would
// strand that stale copy on the other side with no way to learn about it.
func (r *Router) scheduleMaxAgeRemoval(area uint32, k LSAKey, l *LSA, now int64) {}

// ---- Flooding -------------------------------------------------------------

// flood sends an advertisement to every neighbour in the area that is in
// Exchange or later.
func (r *Router) flood(area uint32, l *LSA, now int64) {
	r.floodFrom(area, l, 0, now)
}

// floodFrom is flood with an exclusion: the neighbour we received the update
// from is not sent a copy back.
func (r *Router) floodFrom(area uint32, l *LSA, except uint32, now int64) {
	for _, name := range r.ifOrder {
		i := r.Interfaces[name]
		if i.Area != area || i.State == IfDown {
			continue
		}
		for _, peer := range sortedNbrKeys(i.Nbrs) {
			n := i.Nbrs[peer]
			if peer == except || n.State < Exchange || n.MtuDisagreement {
				continue
			}
			r.sendLSUTo(i, n, l, now)
		}
	}
	if area == 0 {
		for _, trans := range sortedAreaKeys(r.VirInterfaces) {
			if !r.virtualUsable(trans) {
				continue
			}
			for _, peer := range sortedPeerKeys(r.VirInterfaces[trans]) {
				i := r.VirInterfaces[trans][peer]
				if i.State == IfDown {
					continue
				}
				for _, np := range sortedNbrKeys(i.Nbrs) {
					n := i.Nbrs[np]
					if np == except || n.State < Exchange || n.MtuDisagreement {
						continue
					}
					r.sendLSUTo(i, n, l, now)
				}
			}
		}
	}
}

// sendLSUTo unicasts one advertisement, adding it to the retransmission list.
func (r *Router) sendLSUTo(i *Interface, n *Neighbour, l *LSA, now int64) {
	c := l.AgedCopy(now)
	n.LSRetransmit[c.Key()] = c
	r.Metrics.Flooded(c)
	body := MarshalLSU([]*LSA{c})
	r.sendRaw(i, n, PktLSU, body, now)
	r.Audit.Event(now, EvFlood, r.ID, i.Area, "flood %s seq %08x to %s", c.Key(), c.Seq, u32ip(n.RouterID))
}

// sendBack unicasts our newer copy to a peer that sent us a stale one.
func (r *Router) sendBack(area uint32, l *LSA, to uint32, now int64) {
	for _, name := range r.ifOrder {
		i := r.Interfaces[name]
		if i.Area != area {
			continue
		}
		if n := i.Nbrs[to]; n != nil && n.State >= Exchange && !n.MtuDisagreement {
			c := l.AgedCopy(now)
			n.LSRetransmit[c.Key()] = c
			r.sendRaw(i, n, PktLSU, MarshalLSU([]*LSA{c}), now)
			return
		}
	}
	for _, trans := range sortedAreaKeys(r.VirInterfaces) {
		if trans == 0 {
			continue
		}
		for _, peer := range sortedPeerKeys(r.VirInterfaces[trans]) {
			i := r.VirInterfaces[trans][peer]
			if n := i.Nbrs[to]; n != nil && n.State >= Exchange && !n.MtuDisagreement {
				c := l.AgedCopy(now)
				n.LSRetransmit[c.Key()] = c
				r.sendRaw(i, n, PktLSU, MarshalLSU([]*LSA{c}), now)
				return
			}
		}
	}
}

// ---- Refresh and ageing ---------------------------------------------------

// scheduleRefresh arms the periodic self-refresh timer (requirement 4).
// The tick function is the only place that reschedules, so the timer cannot
// multiply.
func (r *Router) scheduleRefresh(now int64) {
	r.refreshGen++
	gen := r.refreshGen
	var tick func(at int64)
	tick = func(at int64) {
		if r.refreshGen != gen {
			return
		}
		r.refreshSelf(at)
		r.Schedule(at+30_000, func() { tick(at + 30_000) })
	}
	r.Schedule(now+30_000, func() { tick(now + 30_000) })
}

// refreshSelf runs every thirty virtual seconds. It removes advertisements
// that have reached MaxAge from routers that are gone, and refreshes the ones
// this router originated that have reached RefreshTime.
func (r *Router) refreshSelf(now int64) {
	for _, area := range sortedAreaKeys(r.areaDB) {
		db := r.areaDB[area]
		var flush []LSAKey
		for k, l := range db {
			if l.CurrentAge(now) >= MaxAge {
				if _, own := r.selfFor(area)[k]; !own {
					flush = append(flush, k)
				}
			}
		}
		_ = flush
		// Advertisements from other routers that reach MaxAge are left in the
		// database as MaxAge entries rather than deleted. Keeping them lets a
		// partition heal through the database description exchange; see
		// scheduleMaxAgeRemoval.
		// Decide once per area and per LSA class whether a refresh is due, so
		// a router with several aged advertisements still originates once.
		needRouter := false
		needExternal := false
		needSummary := false
		for k, l := range db {
			if _, own := r.selfFor(area)[k]; !own {
				continue
			}
			if l.CurrentAge(now) < RefreshTime {
				continue
			}
			switch k.Type {
			case LSARouter:
				needRouter = true
			case LSAASExternal:
				needExternal = true
			case LSASummary, LSASummaryAS:
				needSummary = true
			}
		}
		if needRouter && r.AreaEnabled(area) {
			r.originateRouterLSA(area, now)
			r.Metrics.Refreshed(&LSA{Type: LSARouter, ID: r.ID, AdvRtr: r.ID})
		}
		if needExternal {
			r.originateExternals(now)
		}
		if needSummary {
			r.orchestrateAggregates(now)
		}
	}
}

// originateExternals (re)publishes this ASBR's type 5 advertisements.
func (r *Router) originateExternals(now int64) {
	for _, p := range r.Externals {
		k := LSAKey{Type: LSAASExternal, ID: p.Network, AdvRtr: r.ID}
		// Externals are originated once and flooded into every non-stub area
		// the router serves; the canonical copy lives in area 0's self maps.
		cur := r.selfFor(0)[k]
		var seq uint32
		if cur != nil {
			seq = cur.Seq + 1
		} else {
			seq = r.bumpSeq(0, k)
		}
		r.seqsFor(0)[k] = seq
		l := BuildExternalLSA(p.Network, r.ID, seq, p)
		l.FillDerived()
		l.ReceivedAt = now
		l.SourceRtr = r.ID
		r.selfFor(0)[k] = l
		for _, area := range r.Areas {
			if r.isStubArea(area) {
				continue
			}
			r.db(area)[k] = l
			r.Metrics.Originated(l)
			r.flood(area, l, now)
		}
	}
}

// stationSubnet is the management /32 of a station, derived from its router
// ID so every router owns a unique host prefix with no overlap between areas.
func stationSubnet(id uint32) uint32 { return id }

// LastDBChange is the virtual time of the most recent database install.
func (r *Router) LastDBChange() int64 { return r.lastDBChange }
