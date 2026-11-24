package ospf

import (
	"fmt"
	"sort"
)

// ---- Hello handling -------------------------------------------------------

func (r *Router) handleHello(i *Interface, from uint32, body []byte, now int64) {
	if from == r.ID {
		r.Metrics.Drop("hello-self")
		return
	}
	h, err := UnmarshalHello(body)
	if err != nil {
		r.Metrics.Drop("hello-parse")
		return
	}
	if h.HelloInterval != uint16(i.HelloIntervalMs/1000) ||
		h.DeadInterval != uint16(i.DeadIntervalMs/1000) {
		r.Metrics.Drop("hello-timer-mismatch")
		return
	}
	n := i.Nbrs[from]
	if n == nil {
		n = i.newNeighbour(from, now)
	}
	n.LastHello = now
	n.HellosRecv++
	n.Options = h.Options
	n.Priority = h.RouterPriority

	// (Re)start the inactivity timer. The generation counter makes stale
	// timers harmless without having to remove heap entries.
	n.InactivityGen++
	gen := n.InactivityGen
	deadline := now + i.DeadIntervalMs
	r.Schedule(deadline, func() {
		if n.InactivityGen != gen || n.State == Down {
			return
		}
		r.nbrEvent(i, n, NbrEventInactivityTimer, deadline)
	})

	r.nbrEvent(i, n, NbrEventHelloReceived, now)

	// Two-way check: the peer must list our router ID.
	twoWay := false
	for _, id := range h.Neighbours {
		if id == r.ID {
			twoWay = true
			break
		}
	}
	if twoWay {
		r.nbrEvent(i, n, NbrEvent2WayReceived, now)
		if n.State == TwoWay {
			r.nbrEvent(i, n, NbrEventAdjOK, now)
		}
	} else {
		r.nbrEvent(i, n, NbrEvent1WayReceived, now)
	}
}

// ---- State machine --------------------------------------------------------

// nbrEvent drives the neighbour state machine. It validates every transition
// against the published table and records it in the audit log.
func (r *Router) nbrEvent(i *Interface, n *Neighbour, ev NeighbourEvent, now int64) {
	from := n.State
	to := from
	switch ev {
	case NbrEventHelloReceived:
		if from == Down {
			to = Init
		}
	case NbrEvent2WayReceived:
		switch from {
		case Init:
			to = TwoWay
		case Attempt:
			to = TwoWay
		}
	case NbrEventAdjOK:
		switch from {
		case TwoWay, Init, Attempt:
			to = ExStart
		}
	case NbrEventAdjFail:
		switch from {
		case ExStart, Exchange, Loading, Full:
			to = TwoWay
		}
	case NbrEventNegotiationDone:
		if from == ExStart {
			to = Exchange
		}
	case NbrEventExchangeDone:
		if from == Exchange {
			if r.loadingNeeded(n) {
				to = Loading
			} else {
				to = Full
			}
		}
	case NbrEventLoadingDone:
		if from == Loading {
			to = Full
		}
	case NbrEvent1WayReceived:
		switch from {
		case TwoWay, ExStart, Exchange, Loading, Full:
			to = Init
		}
	case NbrEventBadLSReq, NbrEventSeqNumberMismatch:
		switch from {
		case Exchange, Loading, Full:
			to = ExStart
		}
	case NbrEventKillNbr, NbrEventInactivityTimer, NbrEventLLDown:
		to = Down
	}

	if to != from {
		if allowed := EventAllowedStates(from, ev); allowed == nil {
			panic(fmt.Sprintf("event %s not in table for state %s", ev, from))
		} else {
			ok := false
			for _, s := range allowed {
				if s == to {
					ok = true
				}
			}
			if !ok {
				panic(fmt.Sprintf("illegal transition %s --%s--> %s", from, ev, to))
			}
		}
		rec := TransitionRecord{Router: r.ID, Nbr: n.RouterID, From: from, Event: ev, To: to, At: now}
		if err := r.Audit.Transition(rec); err != nil {
			panic(err)
		}
		r.Audit.Event(now, EvNbrChange, r.ID, i.Area, "nbr %s %s -> %s (%s)", u32ip(n.RouterID), from, to, ev)
		n.State = to
		n.StateSince = now
		switch to {
		case Down:
			// Kill the retransmission timer chain so the next ExStart arms a
			// fresh one; without this reset a neighbour that flaps would never
			// retransmit again and the database exchange would stall.
			n.TimerGen++
			n.timerArmed = false
			r.clearNeighbour(i, n)
			n.DDHeads = map[LSAKey]LSAHead{}
			n.DBSumSent = map[LSAKey]bool{}
			n.LoadingKeys = nil
			n.LSRequests = map[LSAKey]int64{}
			n.LSRetransmit = map[LSAKey]*LSA{}
			n.Master = false
			n.MtuDisagreement = false
		case Init:
			n.DDHeads = map[LSAKey]LSAHead{}
			n.DBSumSent = map[LSAKey]bool{}
			n.LoadingKeys = nil
			n.LSRequests = map[LSAKey]int64{}
			n.LSRetransmit = map[LSAKey]*LSA{}
			n.MtuDisagreement = false
		case ExStart:
			r.startExStart(i, n, now)
		case Exchange:
			// Started by the DD handler after negotiation.
		case Full:
			r.Audit.Event(now, EvNbrChange, r.ID, i.Area, "adjacency with %s FULL", u32ip(n.RouterID))
			// Re-flood anything the neighbour's database description showed it
			// was missing or holding an older copy of. This is the reliable
			// delivery step that closes any gap left by a link that flapped
			// while an advertisement was in flight.
			r.syncNeighbourOnFull(i, n, now)
		}
	}
}

// clearNeighbour removes any pending protocol state for a dead neighbour.
func (r *Router) clearNeighbour(i *Interface, n *Neighbour) {
	n.DDList = nil
	n.DDIndex = 0
	n.SlaveSentFinal = false
	n.MasterSentFinal = false
}

// startExStart performs master/slave election by router ID and, for the
// master, sends the initial empty Database Description packet.
func (r *Router) startExStart(i *Interface, n *Neighbour, now int64) {
	n.DDHeads = map[LSAKey]LSAHead{}
	n.DBSumSent = map[LSAKey]bool{}
	n.Master = r.ID > n.RouterID
	n.DDSeq = InitialDDSeq
	n.SlaveSentFinal = false
	n.MasterSentFinal = false
	if n.Master {
		body := MarshalDD(DDBody{
			MTU:     uint16(i.Mtu),
			Options: r.areaOptions(i.Area),
			I:       true,
			M:       true,
			MS:      true,
			DDSeq:   n.DDSeq,
		}, nil)
		n.LastDDBody = body
		n.LastDDSeq = n.DDSeq
		n.LastDDAt = now
		r.sendDD(i, n, body, now)
	}
	r.startNbrTimer(i, n, now)
}

// startNbrTimer arms the periodic retransmission timer for a neighbour.
func (r *Router) startNbrTimer(i *Interface, n *Neighbour, now int64) {
	if n.timerArmed {
		return
	}
	n.timerArmed = true
	n.TimerGen++
	gen := n.TimerGen
	var tick func(at int64)
	tick = func(at int64) {
		if n.TimerGen != gen || n.State == Down {
			return
		}
		r.nbrTick(i, n, at)
		r.Schedule(at+RetransmitMs, func() { tick(at + RetransmitMs) })
	}
	r.Schedule(now+RetransmitMs, func() { tick(now + RetransmitMs) })
}

// nbrTick retransmits anything still unacknowledged.
func (r *Router) nbrTick(i *Interface, n *Neighbour, now int64) {
	// Deadlock breaker: if the database exchange has made no progress for
	// several retransmission intervals, the two sides have desynchronised
	// their sequence numbers (typically after a flapping link). The master
	// starts a brand new exchange with a higher sequence number, which the
	// slave detects and follows.
	if n.State == ExStart && now-n.StateSince > 6*RetransmitMs {
		if n.Master {
			n.DDSeq += 0x100
			n.StateSince = now
			body := MarshalDD(DDBody{
				MTU: uint16(i.Mtu), Options: r.areaOptions(i.Area),
				I: true, M: true, MS: true, DDSeq: n.DDSeq,
			}, nil)
			n.LastDDBody = body
			n.LastDDSeq = n.DDSeq
			r.sendDD(i, n, body, now)
			r.Audit.Event(now, EvNbrChange, r.ID, i.Area,
				"database exchange with %s restarted (stuck in ExStart)", u32ip(n.RouterID))
		} else {
			// A slave with no master packet for several intervals: the peer
			// has drifted past the exchange. Send a fresh initial reply; the
			// master treats any I-bit packet outside ExStart as a peer restart
			// and renegotiates, which brings both sides back into step.
			n.StateSince = now
			r.sendDDSlaveReply(i, n, true, now)
			r.Audit.Event(now, EvNbrChange, r.ID, i.Area,
				"database exchange with %s restarted (slave, no master packet)", u32ip(n.RouterID))
		}
	}
	if n.State == ExStart || n.State == Exchange {
		if n.LastDDBody != nil && now-n.LastDDAt >= RetransmitMs {
			r.sendDD(i, n, n.LastDDBody, now)
			n.LastDDAt = now
		}
	}
	// Link state requests that have not been answered.
	var retry []LSAKey
	for k, due := range n.LSRequests {
		if now >= due {
			retry = append(retry, k)
		}
	}
	if len(retry) > 0 {
		sortKeys(retry)
		body := MarshalLSR(retry)
		r.sendRaw(i, n, PktLSR, body, now)
		for _, k := range retry {
			n.LSRequests[k] = now + RetransmitMs
		}
	}
	// Advertisements awaiting acknowledgement.
	if len(n.LSRetransmit) > 0 {
		keys := make([]LSAKey, 0, len(n.LSRetransmit))
		for k := range n.LSRetransmit {
			keys = append(keys, k)
		}
		sortKeys(keys)
		var lsas []*LSA
		for _, k := range keys {
			l := n.LSRetransmit[k]
			lsas = append(lsas, l.AgedCopy(now))
			r.Metrics.Retransmitted(l)
		}
		for start := 0; start < len(lsas); start += LSUChunk {
			end := start + LSUChunk
			if end > len(lsas) {
				end = len(lsas)
			}
			body := MarshalLSU(lsas[start:end])
			r.sendRaw(i, n, PktLSU, body, now)
		}
	}
}

// ---- Database Description exchange ----------------------------------------

func (r *Router) sendDD(i *Interface, n *Neighbour, body []byte, now int64) {
	r.Metrics.Sent[PktDD]++
	r.transmit(i, n.RouterID, &Packet{Type: PktDD, Src: r.ID, SrcArea: i.Area, Body: body}, PacketSize(PktDD, len(body)))
	n.LastDDAt = now
}

// sendDDChunk sends the next summary chunk for the neighbour.
func (r *Router) sendDDChunk(i *Interface, n *Neighbour, now int64) {
	heads := r.ddHeadsFor(n)
	more := r.hasMoreDD(n)
	body := MarshalDD(DDBody{
		MTU:     uint16(i.Mtu),
		Options: r.areaOptions(i.Area),
		MS:      n.Master,
		M:       more,
		DDSeq:   n.DDSeq,
	}, heads)
	if !more {
		n.MasterSentFinal = true
	}
	n.LastDDBody = body
	n.LastDDSeq = n.DDSeq
	n.LastDDAt = now
	r.sendDD(i, n, body, now)
}

// sendDDSlaveReply sends the slave's summary chunk echoing the master's seq.
func (r *Router) sendDDSlaveReply(i *Interface, n *Neighbour, initial bool, now int64) {
	heads := r.ddHeadsFor(n)
	more := r.hasMoreDD(n)
	body := MarshalDD(DDBody{
		MTU:     uint16(i.Mtu),
		Options: r.areaOptions(i.Area),
		I:       initial,
		M:       more,
		MS:      false,
		DDSeq:   n.DDSeq,
	}, heads)
	if !more {
		n.SlaveSentFinal = true
	}
	n.LastDDBody = body
	n.LastDDSeq = n.DDSeq
	n.LastDDAt = now
	r.sendDD(i, n, body, now)
}

// sendDDPoll sends the master's empty poll packet so the slave can finish.
func (r *Router) sendDDPoll(i *Interface, n *Neighbour, now int64) {
	body := MarshalDD(DDBody{
		MTU:     uint16(i.Mtu),
		Options: r.areaOptions(i.Area),
		MS:      true,
		M:       false,
		DDSeq:   n.DDSeq,
	}, nil)
	n.MasterSentFinal = true
	n.LastDDBody = body
	n.LastDDSeq = n.DDSeq
	n.LastDDAt = now
	r.sendDD(i, n, body, now)
}

// handleDD processes a Database Description packet.
//
// The exchange is master/slave: the master numbers every Database Description
// packet and the slave echoes that number, which makes duplicates and lost
// packets unambiguous. A packet with a stale number is answered by resending
// our last packet; a packet with the initial sequence number outside ExStart
// means the peer restarted, so both sides renegotiate.
func (r *Router) handleDD(i *Interface, from uint32, body []byte, now int64) {
	n := i.Nbrs[from]
	if n == nil {
		r.Metrics.Drop("dd-no-nbr")
		return
	}
	d, heads, err := UnmarshalDD(body)
	if err != nil {
		r.Metrics.Drop("dd-parse")
		return
	}
	if n.State < ExStart {
		return
	}
	// Requirement 2: the interface MTU travels in DD packets. A mismatch
	// stops the adjacency in Exchange and is reported on the page.
	if d.MTU != uint16(i.Mtu) {
		first := !n.MtuDisagreement
		n.MtuDisagreement = true
		n.MtuLocal = i.Mtu
		n.MtuRemote = int(d.MTU)
		// Move to Exchange and stop there. Sending one Database Description
		// back carries our own MTU, so the peer detects the mismatch too and
		// the two sides agree on the stuck state instead of one waiting in
		// ExStart for a reply that will never come.
		if n.State == ExStart {
			r.nbrEvent(i, n, NbrEventNegotiationDone, now)
		}
		if first {
			r.Audit.Event(now, EvStuck, r.ID, i.Area,
				"adjacency with %s stuck in %s: MTU mismatch (local %d, remote %d)",
				u32ip(from), n.State, i.Mtu, d.MTU)
			body := MarshalDD(DDBody{
				MTU: uint16(i.Mtu), Options: r.areaOptions(i.Area),
				MS: n.Master, DDSeq: n.DDSeq,
			}, nil)
			r.sendDD(i, n, body, now)
		}
		return
	}
	if n.State == ExStart {
		r.ddNegotiate(i, n, d, heads, now)
		return
	}
	// Outside ExStart an initial packet means the peer restarted the exchange
	// (it lost our replies). Only a restarted peer sends I=1 at this point.
	if d.I {
		r.Audit.Event(now, EvNbrChange, r.ID, i.Area,
			"neighbour %s restarted the database exchange", u32ip(from))
		r.nbrEvent(i, n, NbrEventSeqNumberMismatch, now)
		return
	}
	r.ddExchange(i, n, d, heads, now)
}

func (r *Router) ddNegotiate(i *Interface, n *Neighbour, d DDBody, heads []LSAHead, now int64) {
	if n.Master {
		if d.MS {
			// Both sides claimed mastery because the initial packets crossed.
			// The higher router ID keeps it; the lower one becomes the slave
			// and adopts the winner's sequence number.
			if r.ID < n.RouterID {
				n.Master = false
				n.DDSeq = d.DDSeq
				n.MasterSentFinal = false
				r.nbrEvent(i, n, NbrEventNegotiationDone, now)
				r.sendDDSlaveReply(i, n, true, now)
			}
			return
		}
		// The slave's first reply echoes our initial sequence number and may
		// set the I bit (RFC 2328 appendix A.4). Its summaries are the first
		// chunk of the slave's database and must be recorded before we advance
		// the sequence, or the slave's advertisements would never be
		// requested and the two databases would never converge.
		//
		// If the slave's sequence is ahead of ours, the two sides started from
		// different exchanges (one side re-entered ExStart after a flap while
		// the other kept its old sequence). Re-synchronise on the higher
		// number and restart the negotiation from there; otherwise the master
		// would wait forever for a sequence it never issued.
		if d.DDSeq > n.DDSeq {
			n.DDSeq = d.DDSeq
			r.sendDDChunk(i, n, now)
			return
		}
		if d.DDSeq != n.DDSeq {
			return
		}
		r.ddProcessHeads(i, n, heads, now)
		r.nbrEvent(i, n, NbrEventNegotiationDone, now)
		n.DDSeq++
		r.sendDDChunk(i, n, now)
		return
	}
	// Slave: wait for a master packet. Normally this is the initial packet
	// with the I bit set, but after a one-sided reset the master may already
	// be past ExStart; any master packet is enough to adopt its sequence and
	// reply.
	if !d.MS {
		return
	}
	n.DDSeq = d.DDSeq
	n.MasterSentFinal = false
	r.nbrEvent(i, n, NbrEventNegotiationDone, now)
	r.sendDDSlaveReply(i, n, d.I, now)
}

func (r *Router) ddExchange(i *Interface, n *Neighbour, d DDBody, heads []LSAHead, now int64) {
	if n.Master {
		if d.MS {
			// Peer still claims mastery; our retransmission timer will sort
			// it out.
			return
		}
		if d.DDSeq != n.DDSeq {
			// A duplicate of a packet we already answered: repeat our last
			// packet so the slave can make progress.
			if n.LastDDBody != nil {
				r.sendDD(i, n, n.LastDDBody, now)
			}
			return
		}
		r.ddProcessHeads(i, n, heads, now)
		if n.MasterSentFinal && !d.M {
			// The slave acknowledged our final packet and is done too.
			r.nbrEvent(i, n, NbrEventExchangeDone, now)
			r.startLoading(i, n, now)
			return
		}
		n.DDSeq++
		if r.hasMoreDD(n) {
			r.sendDDChunk(i, n, now)
		} else {
			r.sendDDPoll(i, n, now)
		}
		return
	}
	// Slave.
	if !d.MS {
		return
	}
	if d.DDSeq != n.DDSeq {
		if seqGT(d.DDSeq, n.DDSeq) {
			n.DDSeq = d.DDSeq
		} else {
			// Stale master packet: repeat our last reply.
			if n.LastDDBody != nil {
				r.sendDD(i, n, n.LastDDBody, now)
			}
			return
		}
	}
	r.ddProcessHeads(i, n, heads, now)
	// Always answer with a summary chunk; the reply doubles as the
	// acknowledgement for the master's packet.
	r.sendDDSlaveReply(i, n, false, now)
	if n.SlaveSentFinal && !d.M {
		r.nbrEvent(i, n, NbrEventExchangeDone, now)
		r.startLoading(i, n, now)
	}
}

// ddProcessHeads records the peer's summary and queues any requests.
func (r *Router) ddProcessHeads(i *Interface, n *Neighbour, heads []LSAHead, now int64) {
	for _, h := range heads {
		n.DDHeads[h.Key()] = h
	}
}

// startLoading requests every advertisement the peer has that we lack or that
// is older than the peer's copy, then waits for the Updates to arrive.
func (r *Router) startLoading(i *Interface, n *Neighbour, now int64) {
	if n.State != Loading {
		// ExchangeDone decided we are already Full.
		return
	}
	keys := r.missingKeys(n, now)
	if len(keys) == 0 {
		r.nbrEvent(i, n, NbrEventLoadingDone, now)
		return
	}
	n.LoadingKeys = append([]LSAKey(nil), keys...)
	for _, k := range keys {
		n.LSRequests[k] = now + RetransmitMs
	}
	for start := 0; start < len(keys); start += 8 {
		end := start + 8
		if end > len(keys) {
			end = len(keys)
		}
		body := MarshalLSR(keys[start:end])
		r.sendRaw(i, n, PktLSR, body, now)
	}
}

// missingKeys computes the LSR list from the peer's DD summary.
func (r *Router) missingKeys(n *Neighbour, now int64) []LSAKey {
	var out []LSAKey
	for k, h := range n.DDHeads {
		local := r.Lookup(n.area, k)
		if local == nil {
			out = append(out, k)
			continue
		}
		remote := &LSA{Age: h.Age, Type: h.Type, ID: h.ID, AdvRtr: h.AdvRtr,
			Seq: h.Seq, Checksum: h.Checksum, Length: h.Length}
		if LSACompare(remote, local.AgedCopy(now)) > 0 {
			out = append(out, k)
		}
	}
	sortKeys(out)
	return out
}

// loadingNeeded is consulted by the ExchangeDone transition.
func (r *Router) loadingNeeded(n *Neighbour) bool {
	return len(r.missingKeys(n, r.Now())) > 0
}

// ---- Link State Request / Update / Ack -----------------------------------

func (r *Router) handleLSR(i *Interface, from uint32, body []byte, now int64) {
	n := i.Nbrs[from]
	if n == nil || n.State < Exchange {
		r.Metrics.Drop("lsr-state")
		return
	}
	keys := UnmarshalLSR(body)
	var lsas []*LSA
	bad := false
	for _, k := range keys {
		l := r.Lookup(i.Area, k)
		if l == nil {
			bad = true
			continue
		}
		lsas = append(lsas, l.AgedCopy(now))
	}
	if bad {
		r.nbrEvent(i, n, NbrEventBadLSReq, now)
		return
	}
	if len(lsas) == 0 {
		return
	}
	for _, l := range lsas {
		n.LSRetransmit[l.Key()] = l
	}
	for start := 0; start < len(lsas); start += LSUChunk {
		end := start + LSUChunk
		if end > len(lsas) {
			end = len(lsas)
		}
		r.sendRaw(i, n, PktLSU, MarshalLSU(lsas[start:end]), now)
	}
}

// handleLSU processes a Link State Update.
func (r *Router) handleLSU(i *Interface, from uint32, body []byte, now int64) {
	n := i.Nbrs[from]
	if n == nil || n.State < Exchange {
		r.Metrics.Drop("lsu-state")
		return
	}
	lsas, err := UnmarshalLSU(body)
	if err != nil {
		r.Metrics.Drop("lsu-parse")
		return
	}
	r.Metrics.Recv[PktLSU]++
	acks := make([]LSAHead, 0, len(lsas))
	for _, l := range lsas {
		if l.Type == LSAASExternal && r.isStubArea(i.Area) {
			// Requirement 8: external advertisements never enter a stub area.
			r.Metrics.Drop("external-in-stub")
			continue
		}
		l.ReceivedAt = now
		l.SourceRtr = from
		r.Metrics.Received(l)
		r.installLSA(i.Area, l, from, now)
		acks = append(acks, HeadOf(l))
		if n.State == Loading {
			delete(n.LSRequests, l.Key())
			r.removeLoadingKey(n, l.Key())
		}
	}
	if len(acks) > 0 {
		r.sendRaw(i, n, PktLSAck, MarshalLSAck(acks), now)
	}
	if n.State == Loading && len(n.LoadingKeys) == 0 && len(n.LSRequests) == 0 {
		r.nbrEvent(i, n, NbrEventLoadingDone, now)
	}
}

func (r *Router) removeLoadingKey(n *Neighbour, k LSAKey) {
	out := n.LoadingKeys[:0]
	for _, x := range n.LoadingKeys {
		if x != k {
			out = append(out, x)
		}
	}
	n.LoadingKeys = out
}

// handleLSAck removes acknowledged advertisements from the retransmit list.
func (r *Router) handleLSAck(i *Interface, from uint32, body []byte, now int64) {
	n := i.Nbrs[from]
	if n == nil {
		return
	}
	r.Metrics.Recv[PktLSAck]++
	for _, h := range UnmarshalLSAck(body) {
		if l, ok := n.LSRetransmit[h.Key()]; ok && l.Seq == h.Seq {
			delete(n.LSRetransmit, h.Key())
			r.ackMatched++
		} else if ok {
			r.ackMismatch++
		}
	}
}

// sendRaw is the ordinary unicast transmit path for non-DD packets.
func (r *Router) sendRaw(i *Interface, n *Neighbour, typ uint8, body []byte, now int64) {
	r.Metrics.Sent[typ]++
	r.transmit(i, n.RouterID, &Packet{Type: typ, Src: r.ID, SrcArea: i.Area, Body: body}, PacketSize(typ, len(body)))
}

// ---- Helper predicates ----------------------------------------------------

func (r *Router) isStubArea(area uint32) bool {
	a := r.Topo.Areas[area]
	return a != nil && (a.Type == StubArea || a.Type == TotallyStubArea)
}

func sortKeys(keys []LSAKey) {
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.AdvRtr < b.AdvRtr
	})
}

// syncNeighbourOnFull pushes our copies of advertisements that the neighbour
// reported (in its database description) as missing or older. Reliability is
// completed through the normal retransmission list, so a lost packet is
// retried until acknowledged.
func (r *Router) syncNeighbourOnFull(i *Interface, n *Neighbour, now int64) {
	db := r.areaDB[n.area]
	var keys []LSAKey
	for k := range db {
		if _, pending := n.LSRetransmit[k]; pending {
			continue
		}
		if theirs, ok := n.DDHeads[k]; ok {
			remote := &LSA{Age: theirs.Age, Type: theirs.Type, ID: theirs.ID, AdvRtr: theirs.AdvRtr,
				Seq: theirs.Seq, Checksum: theirs.Checksum, Length: theirs.Length}
			if LSACompare(db[k].AgedCopy(now), remote) <= 0 {
				continue
			}
		}
		keys = append(keys, k)
	}
	sortKeys(keys)
	for _, k := range keys {
		r.sendLSUTo(i, n, db[k], now)
	}
}
