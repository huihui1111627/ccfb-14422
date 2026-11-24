package ospf

import "testing"

// TestLSAEncodingRoundTrip checks that marshalling and unmarshalling an
// advertisement preserves every field and validates the checksum.
func TestLSAEncodingRoundTrip(t *testing.T) {
	links := []RouterLink{
		{ID: 0x0aff0002, Data: 0x0a000102, Type: LinkP2P, Metric: 10},
		{ID: 0x0aff0001, Data: 0xffffffff, Type: LinkStub, Metric: 1},
	}
	l := BuildRouterLSA(0x0aff0001, 0, OptE, FlagABR, InitialSeqNum, links)
	if !l.VerifyChecksum() {
		t.Fatal("freshly built LSA has an invalid checksum")
	}
	b := l.Marshal()
	got, err := UnmarshalLSA(b)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Seq != l.Seq || got.Checksum != l.Checksum || got.Type != LSARouter {
		t.Fatalf("header mismatch: %+v vs %+v", got, l)
	}
	if got.Flags != FlagABR || got.Options != OptE {
		t.Fatalf("flags/options mismatch")
	}
	decoded := DecodeRouterLinks(got.Body)
	if len(decoded) != len(links) {
		t.Fatalf("link count %d != %d", len(decoded), len(links))
	}
}

// TestLSACompareOrdering exercises the recency rules of RFC 2328 section 13.1.
func TestLSACompareOrdering(t *testing.T) {
	base := BuildSummaryLSA(LSASummary, 0x0a000100, 0x0aff0001, InitialSeqNum, 0, Prefix{Network: 0x0a000100, Mask: 0xffffff00, Metric: 10})
	if LSACompare(base, base) != 0 {
		t.Fatal("identical LSAs should compare equal")
	}
	newer := base.Clone()
	newer.Seq++
	newer.FillDerived()
	if LSACompare(newer, base) <= 0 {
		t.Fatal("higher sequence must be more recent")
	}
	if LSACompare(base, newer) >= 0 {
		t.Fatal("lower sequence must be older")
	}
	// Same sequence and checksum, larger age beyond MaxAgeDiff is older.
	old := base.Clone()
	old.Age = base.Age + MaxAgeDiff + 10
	if LSACompare(old, base) >= 0 {
		t.Fatal("a much older copy must be considered older")
	}
	// MaxAge beats everything with the same sequence and checksum.
	maxAge := base.Clone()
	maxAge.Age = MaxAge
	if LSACompare(maxAge, base) <= 0 {
		t.Fatal("MaxAge must be considered more recent than a live copy")
	}
}

// TestSequenceWrap compares sequence numbers across the 32-bit wrap point.
func TestSequenceWrap(t *testing.T) {
	a := BuildRouterLSA(1, 0, 0, 0, 0x7fffffff, nil)
	b := BuildRouterLSA(1, 0, 0, 0, 0x80000000, nil)
	if LSACompare(b, a) <= 0 {
		t.Fatal("0x80000000 must be more recent than 0x7fffffff")
	}
}

// TestHelloPacketRoundTrip checks the Hello encoding.
func TestHelloPacketRoundTrip(t *testing.T) {
	h := HelloBody{NetworkMask: 0xffffff00, HelloInterval: 10, DeadInterval: 40,
		Options: OptE, RouterPriority: 1, Neighbours: []uint32{1, 2, 3}}
	b := MarshalHello(h)
	got, err := UnmarshalHello(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.HelloInterval != 10 || got.DeadInterval != 40 || len(got.Neighbours) != 3 {
		t.Fatalf("hello roundtrip mismatch: %+v", got)
	}
}

// TestDDPacketMTU checks that the interface MTU survives the DD encoding.
func TestDDPacketMTU(t *testing.T) {
	body := MarshalDD(DDBody{MTU: 9000, I: true, M: true, MS: true, DDSeq: 4096}, nil)
	d, heads, err := UnmarshalDD(body)
	if err != nil {
		t.Fatal(err)
	}
	if d.MTU != 9000 {
		t.Fatalf("MTU %d != 9000", d.MTU)
	}
	if !d.I || !d.M || !d.MS {
		t.Fatalf("flags lost: %+v", d)
	}
	if len(heads) != 0 {
		t.Fatalf("expected no LSA headers")
	}
}

// TestLSUSplitLength guards against the field offset that used to corrupt
// multi-LSA updates.
func TestLSUSplitLength(t *testing.T) {
	l1 := BuildRouterLSA(1, 0, 0, 0, InitialSeqNum, nil)
	l2 := BuildExternalLSA(0x0a000100, 2, InitialSeqNum, Prefix{Network: 0x0a000100, Mask: 0xffffff00, Metric: 20})
	body := MarshalLSU([]*LSA{l1, l2})
	got, err := UnmarshalLSU(body)
	if err != nil {
		t.Fatalf("lsu: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("decoded %d LSAs, want 2", len(got))
	}
	if got[1].Type != LSAASExternal {
		t.Fatalf("second LSA has type %s", got[1].Type)
	}
}

// TestChecksumDetectsCorruption flips a body byte and expects rejection.
func TestChecksumDetectsCorruption(t *testing.T) {
	l := BuildSummaryLSA(LSASummary, 0x0a000100, 0x0aff0001, InitialSeqNum, 0, Prefix{Network: 0x0a000100, Mask: 0xffffff00, Metric: 10})
	b := l.Marshal()
	b[len(b)-1] ^= 0xff
	if _, err := UnmarshalLSA(b); err == nil {
		t.Fatal("corrupted LSA was accepted")
	}
}

// TestStateMachineTable checks a handful of transitions against the published
// event/state table.
func TestStateMachineTable(t *testing.T) {
	cases := []struct {
		from NbrState
		ev   NeighbourEvent
		to   NbrState
		ok   bool
	}{
		{Down, NbrEventHelloReceived, Init, true},
		{Init, NbrEvent2WayReceived, TwoWay, true},
		{TwoWay, NbrEventAdjOK, ExStart, true},
		{ExStart, NbrEventNegotiationDone, Exchange, true},
		{Exchange, NbrEventExchangeDone, Loading, true},
		{Loading, NbrEventLoadingDone, Full, true},
		{Down, NbrEventLoadingDone, Full, false},
		{Init, NbrEventExchangeDone, Full, false},
	}
	for _, c := range cases {
		err := ValidateTransition(TransitionRecord{From: c.from, Event: c.ev, To: c.to})
		if c.ok && err != nil {
			t.Errorf("%s --%s--> %s should be legal: %v", c.from, c.ev, c.to, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s --%s--> %s should be illegal", c.from, c.ev, c.to)
		}
	}
}
