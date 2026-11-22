package core

import "fmt"

// Neighbor FSM states.
type NbrState int

const (
	NbrDown NbrState = iota
	NbrInit
	NbrTwoWay
	NbrExStart
	NbrExchange
	NbrLoading
	NbrFull
)

func (s NbrState) String() string {
	return []string{"Down", "Init", "TwoWay", "ExStart", "Exchange", "Loading", "Full"}[s]
}

// Neighbor is one adjacency endpoint on a point-to-point interface or virtual link.
type Neighbor struct {
	RtrID RouterID
	If    *Interface // nil for virtual links
	VL    *VLink
	R     *Router // owning router

	State  NbrState
	Master bool // we are the master in DD exchange
	DDSeq  uint32

	ddQueue  []*LSA  // headers still to send in DD packets
	lastDD   *Packet // last DD sent (for retransmission)
	ReqList  []LSAKey
	RetxList map[LSAKey]*LSA

	StuckReason string // why the adjacency is not progressing (e.g. MTU mismatch)

	helloTimer *Event
	deadTimer  *Event
	ddRetx     *Event
	lsrRetx    *Event
	lsuRetx    *Event

	VLUp   bool // virtual link transport is up
	VLCost int  // cost across the transit area (virtual links)
}

// Area returns the area this adjacency belongs to.
func (n *Neighbor) Area() AreaID {
	if n.VL != nil {
		return Backbone
	}
	return n.If.Area
}

func (n *Neighbor) send(pkt *Packet) { n.sendP(pkt, false) }

func (n *Neighbor) sendP(pkt *Packet, periodic bool) {
	pkt.Src = n.R.ID
	pkt.Area = n.Area()
	if n.VL != nil {
		n.R.W.sendPacketVL(n.VL, n.R.ID, pkt, periodic)
	} else {
		n.R.W.sendPacket(n.If.Link, n.If, pkt, periodic)
	}
}

// lsdbSnapshot returns the LSA headers to advertise in DD packets:
// the area LSDB plus externals (unless the area is stub).
func (n *Neighbor) lsdbSnapshot() []*LSA {
	r := n.R
	area := n.Area()
	var out []*LSA
	db := r.LSDB[area]
	for _, k := range sortedKeys(db) {
		out = append(out, headerOf(db[k], r.W.Now))
	}
	if ac := r.W.Areas[area]; ac == nil || !ac.Stub {
		for _, k := range sortedKeys(r.ExtDB) {
			out = append(out, headerOf(r.ExtDB[k], r.W.Now))
		}
	}
	return out
}

// --- interface up/down -------------------------------------------------

func (r *Router) ifaceUp(ifc *Interface) {
	r.startHello(ifc)
}

func (r *Router) ifaceDown(ifc *Interface) {
	if ifc.NbrHelloTimer != nil {
		ifc.NbrHelloTimer.Cancel()
		ifc.NbrHelloTimer = nil
	}
	if ifc.Nbr != nil {
		r.killNeighbor(ifc.Nbr)
		ifc.Nbr = nil
	}
	r.originateRouterLSA(ifc.Area)
}

func (r *Router) startHello(ifc *Interface) {
	w := r.W
	send := func() {
		if !ifc.Up() {
			return
		}
		pkt := &Packet{Type: PktHello, Src: r.ID, Area: ifc.Area}
		if ifc.Nbr != nil && ifc.Nbr.State >= NbrInit {
			pkt.Seen = []RouterID{ifc.Nbr.RtrID}
		}
		w.sendPacket(ifc.Link, ifc, pkt, true)
	}
	var ev *Event
	var fn func()
	fn = func() {
		send()
		ev = w.Schedule(w.Cfg.HelloInterval, true, "hello", fn)
		ifc.NbrHelloTimer = ev
	}
	ev = w.Schedule(1, true, "hello", fn)
	ifc.NbrHelloTimer = ev
}

// killNeighbor tears down an adjacency.
func (r *Router) killNeighbor(n *Neighbor) {
	if n.State != NbrDown {
		n.State = NbrDown
		r.W.MarkChange()
	}
	n.StuckReason = ""
	n.ddQueue = nil
	n.lastDD = nil
	n.ReqList = nil
	n.RetxList = make(map[LSAKey]*LSA)
	for _, e := range []*Event{n.deadTimer, n.ddRetx, n.lsrRetx, n.lsuRetx} {
		if e != nil {
			e.Cancel()
		}
	}
	n.deadTimer, n.ddRetx, n.lsrRetx, n.lsuRetx = nil, nil, nil, nil
	r.originateRouterLSA(n.Area())
}

// --- packet dispatch ----------------------------------------------------

func (r *Router) handlePacket(ifc *Interface, pkt *Packet) {
	switch pkt.Type {
	case PktHello:
		r.handleHello(ifc, pkt)
	case PktDD:
		r.handleDD(ifc.Nbr, pkt)
	case PktLSR:
		r.handleLSR(ifc.Nbr, pkt)
	case PktLSU:
		r.handleLSU(ifc.Nbr, pkt)
	case PktLSAck:
		r.handleLSAck(ifc.Nbr, pkt)
	}
}

func (r *Router) handleHello(ifc *Interface, pkt *Packet) {
	w := r.W
	if pkt.Area != ifc.Area {
		return
	}
	n := ifc.Nbr
	if n == nil {
		n = &Neighbor{RtrID: pkt.Src, If: ifc, R: r, State: NbrInit, RetxList: make(map[LSAKey]*LSA)}
		ifc.Nbr = n
		w.MarkChange()
	}
	// (re)arm dead timer
	if n.deadTimer != nil {
		n.deadTimer.Cancel()
	}
	nb := n
	n.deadTimer = w.Schedule(w.Cfg.DeadInterval, true, "dead", func() {
		r.killNeighbor(nb)
		if ifc.Nbr == nb {
			ifc.Nbr = nil
		}
	})
	seenMe := false
	for _, id := range pkt.Seen {
		if id == r.ID {
			seenMe = true
		}
	}
	if seenMe && n.State < NbrTwoWay {
		n.State = NbrTwoWay
		w.MarkChange()
		// point-to-point: always become adjacent
		r.nbrExStart(n)
	}
}

// nbrExStart begins DD master/slave negotiation.
func (r *Router) nbrExStart(n *Neighbor) {
	n.State = NbrExStart
	n.StuckReason = ""
	n.Master = true // tentatively
	n.DDSeq = uint32(r.ID)&0xffff | 1
	r.sendDDEmpty(n, DDFlagI|DDFlagM|DDFlagMS)
	r.armDDRetx(n)
}

func (r *Router) sendDDEmpty(n *Neighbor, flags uint8) {
	pkt := &Packet{Type: PktDD, Flags: flags, DDSeq: n.DDSeq}
	if n.VL != nil {
		pkt.MTU = 1500
	} else {
		pkt.MTU = n.If.MTU
	}
	n.lastDD = pkt
	n.send(pkt)
}

// sendDDChunk sends the next DD packet carrying up to DDChunk headers.
// It reports whether the packet had the M(ore) bit set.
func (r *Router) sendDDChunk(n *Neighbor) bool {
	chunk := n.R.W.Cfg.DDChunk
	pkt := &Packet{Type: PktDD, DDSeq: n.DDSeq}
	if n.VL != nil {
		pkt.MTU = 1500
	} else {
		pkt.MTU = n.If.MTU
	}
	if len(n.ddQueue) > chunk {
		pkt.HeadLSAs = n.ddQueue[:chunk]
		n.ddQueue = n.ddQueue[chunk:]
		pkt.Flags |= DDFlagM
	} else {
		pkt.HeadLSAs = n.ddQueue
		n.ddQueue = nil
	}
	if n.Master {
		pkt.Flags |= DDFlagMS
	}
	n.lastDD = pkt
	n.send(pkt)
	return pkt.Flags&DDFlagM != 0
}

func (r *Router) armDDRetx(n *Neighbor) {
	if n.ddRetx != nil {
		n.ddRetx.Cancel()
	}
	w := r.W
	var fn func()
	fn = func() {
		if n.State == NbrExStart || n.State == NbrExchange {
			if n.lastDD != nil {
				n.sendP(n.lastDD, true)
			}
			n.ddRetx = w.Schedule(w.Cfg.RxmtInterval, true, "dd-retx", fn)
		}
	}
	n.ddRetx = w.Schedule(w.Cfg.RxmtInterval, true, "dd-retx", fn)
}

// handleDD processes a Database Description packet.
func (r *Router) handleDD(n *Neighbor, pkt *Packet) {
	if n == nil || n.State < NbrExStart {
		return
	}
	w := r.W
	// MTU check: mismatched interface MTU stalls the adjacency in ExStart/Exchange.
	localMTU := 1500
	if n.VL == nil {
		localMTU = n.If.MTU
	}
	if pkt.MTU != localMTU {
		reason := fmt.Sprintf("MTU mismatch: local=%d remote=%d", localMTU, pkt.MTU)
		if n.StuckReason != reason {
			n.StuckReason = reason
			w.MarkChange()
		}
		if n.State != NbrExStart {
			n.State = NbrExStart
			n.ddQueue = nil
			n.lastDD = nil
			r.nbrExStart(n)
			w.MarkChange()
		}
		return
	}
	n.StuckReason = ""

	// the peer restarted its database exchange (e.g. after BadLSReq or a
	// fatal mismatch): restart ours too
	if pkt.Flags&DDFlagI != 0 && pkt.Flags&DDFlagMS != 0 && n.State > NbrExStart {
		n.ReqList = nil
		n.ddQueue = nil
		n.lastDD = nil
		r.nbrExStart(n)
	}

	switch n.State {
	case NbrExStart:
		if pkt.Flags&DDFlagI != 0 && pkt.Flags&DDFlagMS != 0 {
			if pkt.Src > r.ID {
				// we are the slave
				n.Master = false
				n.DDSeq = pkt.DDSeq
				n.State = NbrExchange
				n.ddQueue = n.lsdbSnapshot()
				r.sendDDChunk(n)
				w.MarkChange()
			} else if pkt.Src < r.ID {
				// we are the master; wait for the slave's echo of our seq
				n.Master = true
				n.State = NbrExchange
				n.ddQueue = n.lsdbSnapshot()
				w.MarkChange()
			}
		}
	case NbrExchange:
		if n.Master {
			if pkt.Flags&DDFlagMS != 0 || pkt.DDSeq != n.DDSeq {
				return // duplicate or out of window
			}
			r.addToReqList(n, pkt.HeadLSAs)
			n.DDSeq++
			peerMore := pkt.Flags&DDFlagM != 0
			myMore := r.sendDDChunk(n)
			// the exchange is complete only when a full round had both
			// M bits clear: the slave must see our final M=0 packet
			if !peerMore && !myMore {
				r.exchangeDone(n)
			}
		} else {
			if pkt.Flags&DDFlagMS == 0 || pkt.DDSeq != n.DDSeq+1 {
				return
			}
			r.addToReqList(n, pkt.HeadLSAs)
			n.DDSeq++
			peerMore := pkt.Flags&DDFlagM != 0
			myMore := r.sendDDChunk(n)
			if !peerMore && !myMore {
				r.exchangeDone(n)
			}
		}
	}
}

func (r *Router) addToReqList(n *Neighbor, heads []*LSA) {
	for _, h := range heads {
		if h.Body == nil && h.Key.Type == 0 {
			continue
		}
		existing := r.lookupLSA(n.Area(), h.Key)
		if existing == nil || h.NewerThan(existing, r.W.Now, r.W.Cfg.MaxAgeDiff, r.W.Cfg.MaxAge) {
			found := false
			for _, k := range n.ReqList {
				if k == h.Key {
					found = true
					break
				}
			}
			if !found {
				n.ReqList = append(n.ReqList, h.Key)
			}
		}
	}
}

// exchangeDone moves the neighbor to Loading or Full.
func (r *Router) exchangeDone(n *Neighbor) {
	if n.ddRetx != nil {
		n.ddRetx.Cancel()
		n.ddRetx = nil
	}
	if len(n.ReqList) == 0 {
		r.nbrFull(n)
		return
	}
	n.State = NbrLoading
	r.W.MarkChange()
	r.sendLSR(n)
	r.armLSRRetx(n)
}

func (r *Router) sendLSR(n *Neighbor) { r.sendLSRP(n, false) }

func (r *Router) sendLSRP(n *Neighbor, periodic bool) {
	if len(n.ReqList) == 0 {
		return
	}
	pkt := &Packet{Type: PktLSR, Requests: append([]LSAKey(nil), n.ReqList...)}
	n.sendP(pkt, periodic)
}

func (r *Router) armLSRRetx(n *Neighbor) {
	if n.lsrRetx != nil {
		n.lsrRetx.Cancel()
	}
	w := r.W
	var fn func()
	fn = func() {
		if n.State == NbrLoading && len(n.ReqList) > 0 {
			r.sendLSRP(n, true)
			n.lsrRetx = w.Schedule(w.Cfg.RxmtInterval, true, "lsr-retx", fn)
		}
	}
	n.lsrRetx = w.Schedule(w.Cfg.RxmtInterval, true, "lsr-retx", fn)
}

// nbrFull declares the adjacency fully adjacent.
func (r *Router) nbrFull(n *Neighbor) {
	n.State = NbrFull
	n.StuckReason = ""
	r.W.MarkChange()
	r.originateRouterLSA(n.Area())
}

// handleLSR answers a Link State Request with the requested LSAs.
func (r *Router) handleLSR(n *Neighbor, pkt *Packet) {
	if n == nil || n.State < NbrExchange {
		return
	}
	var lsas []*LSA
	bad := false
	for _, k := range pkt.Requests {
		if l := r.lookupLSA(n.Area(), k); l != nil {
			lsas = append(lsas, l)
		} else {
			bad = true
		}
	}
	if bad {
		// BadLSReq: the requested LSA vanished from our database after we
		// advertised it in the DD exchange; restart the exchange so both
		// sides re-synchronize from a fresh snapshot (RFC 2328 10.3)
		n.ReqList = nil
		n.ddQueue = nil
		n.lastDD = nil
		r.nbrExStart(n)
		return
	}
	if len(lsas) > 0 {
		r.sendLSU(n, lsas)
	}
}

// handleLSAck removes acknowledged LSAs from the retransmission list.
func (r *Router) handleLSAck(n *Neighbor, pkt *Packet) {
	if n == nil {
		return
	}
	for _, h := range pkt.LSAs {
		delete(n.RetxList, h.Key)
	}
}

func (r *Router) armLSURetx(n *Neighbor) {
	if n.lsuRetx != nil {
		return // already armed
	}
	w := r.W
	var fn func()
	fn = func() {
		if len(n.RetxList) == 0 || n.State < NbrExchange {
			n.lsuRetx = nil
			return
		}
		var lsas []*LSA
		for _, k := range sortedKeys(n.RetxList) {
			lsas = append(lsas, n.RetxList[k])
		}
		r.sendLSUP(n, lsas, true)
		n.lsuRetx = w.Schedule(w.Cfg.RxmtInterval, true, "lsu-retx", fn)
	}
	n.lsuRetx = w.Schedule(w.Cfg.RxmtInterval, true, "lsu-retx", fn)
}
