package ospf

import (
	"encoding/binary"
	"fmt"
)

// LSAType identifies the kind of link state advertisement.
type LSAType uint8

const (
	LSARouter     LSAType = 1
	LSANetwork    LSAType = 2
	LSASummary    LSAType = 3
	LSASummaryAS  LSAType = 4 // ASBR summary
	LSAASExternal LSAType = 5
	LSANSSA       LSAType = 7
)

func (t LSAType) String() string {
	switch t {
	case LSARouter:
		return "Router"
	case LSANetwork:
		return "Network"
	case LSASummary:
		return "Summary"
	case LSASummaryAS:
		return "ASBR-Summary"
	case LSAASExternal:
		return "AS-External"
	case LSANSSA:
		return "NSSA"
	}
	return fmt.Sprintf("LSA(%d)", uint8(t))
}

// LS age is kept in virtual seconds, exactly like the 16-bit wire field.
const (
	MaxAge        uint16 = 3600
	RefreshTime   uint16 = 1800
	CheckAgeTime  uint16 = 300
	MinLSInterval uint16 = 5
	MaxAgeDiff    uint16 = 900
	InitialSeqNum uint32 = 0x80000001
	MaxSeqNum     uint32 = 0x7fffffff
	LSInfinity    uint32 = 0xffffff
)

// Router LSA flags.
const (
	FlagABR  uint8 = 0x01
	FlagASBR uint8 = 0x02
	FlagVirt uint8 = 0x04
)

// Options bits.
const (
	OptE uint8 = 0x02 // external routing capable
)

// LSA is the canonical in-memory and wire representation of an advertisement.
//
// Layout: a 20 byte header, a 12 byte trailer (Addr, Count, Flags) and a body
// whose interpretation depends on Type:
//
//	Router    -> sequence of 12-byte router links
//	Network   -> sequence of attached router IDs
//	Summary   -> single 12-byte (network, mask, metric) prefix
//	External  -> single 16-byte (network, mask, metric, fwd) prefix
//
// Addr carries the area ID for router LSAs and 0 otherwise.
type LSA struct {
	Age      uint16
	Options  uint8
	Type     LSAType
	ID       uint32
	AdvRtr   uint32
	Seq      uint32
	Checksum uint16
	Length   uint16
	Addr     uint32
	Flags    uint8
	Count    uint32
	Body     []byte

	// Age is the value when the advertisement was stored; ReceivedAt is the
	// virtual millisecond at which that happened. CurrentAge derives the
	// present age from the pair, so ageing costs no periodic work.
	ReceivedAt int64
	// SourceRtr is the router that handed us this copy. Not on the wire.
	SourceRtr uint32
}

// LSAKey is the database key: type, link state ID, advertising router.
type LSAKey struct {
	Type   LSAType
	ID     uint32
	AdvRtr uint32
}

func (l *LSA) Key() LSAKey { return LSAKey{l.Type, l.ID, l.AdvRtr} }

func (k LSAKey) String() string {
	return fmt.Sprintf("%s %s adv %s", k.Type, u32ip(k.ID), u32ip(k.AdvRtr))
}

// Clone deep copies the advertisement.
func (l *LSA) Clone() *LSA {
	c := *l
	c.Body = append([]byte(nil), l.Body...)
	return &c
}

// CurrentAge returns the age in virtual seconds at time now.
func (l *LSA) CurrentAge(now int64) uint16 {
	delta := (now - l.ReceivedAt) / 1000
	if delta < 0 {
		delta = 0
	}
	a := int64(l.Age) + delta
	if a > int64(MaxAge) {
		a = int64(MaxAge)
	}
	return uint16(a)
}

// AgedCopy returns a deep copy whose Age field reflects time now.
func (l *LSA) AgedCopy(now int64) *LSA {
	c := l.Clone()
	c.Age = l.CurrentAge(now)
	return c
}

// ExpireAt is the virtual time at which this copy reaches MaxAge.
func (l *LSA) ExpireAt() int64 {
	remain := int64(MaxAge) - int64(l.Age)
	if remain < 0 {
		remain = 0
	}
	return l.ReceivedAt + remain*1000
}

// SameInstance reports whether two advertisements carry the same instance.
func (l *LSA) SameInstance(o *LSA) bool {
	return l.Type == o.Type && l.ID == o.ID && l.AdvRtr == o.AdvRtr &&
		l.Seq == o.Seq && l.Checksum == o.Checksum && l.Length == o.Length
}

// PayloadEqual compares everything that defines the contents, excluding age.
func (l *LSA) PayloadEqual(o *LSA) bool {
	return l.Type == o.Type && l.ID == o.ID && l.AdvRtr == o.AdvRtr &&
		l.Seq == o.Seq && l.Checksum == o.Checksum && l.Length == o.Length &&
		l.Options == o.Options && l.Addr == o.Addr && l.Flags == o.Flags &&
		l.Count == o.Count && string(l.Body) == string(o.Body)
}

// wire serialises the advertisement with the LS age zeroed. The RFC excludes
// the age from the checksum so a flooded copy can be aged without
// invalidating the checksum.
func (l *LSA) wire() []byte {
	b := make([]byte, 0, 32+len(l.Body))
	// Header layout: age(2) options(1) type(1) id(4) adv(4) seq(4) cksum(2)
	// length(2) = 20 bytes; age and checksum are written by Marshal.
	var hdr [20]byte
	hdr[2] = l.Options
	hdr[3] = byte(l.Type)
	binary.BigEndian.PutUint32(hdr[4:], l.ID)
	binary.BigEndian.PutUint32(hdr[8:], l.AdvRtr)
	binary.BigEndian.PutUint32(hdr[12:], l.Seq)
	binary.BigEndian.PutUint16(hdr[18:], l.Length)
	b = append(b, hdr[:]...)
	var tr [12]byte
	binary.BigEndian.PutUint32(tr[0:], l.Addr)
	binary.BigEndian.PutUint32(tr[4:], l.Count)
	tr[8] = l.Flags
	b = append(b, tr[:]...)
	b = append(b, l.Body...)
	return b
}

// computeChecksum implements RFC 2328 Fletcher-16 over the serialisation
// with the LS age and the checksum field treated as zero.
func computeChecksum(l *LSA) uint16 {
	data := l.wire()
	var c0, c1 uint32
	for i := 0; i < len(data); i++ {
		c0 += uint32(data[i])
		c0 %= 255
		c1 += c0
		c1 %= 255
	}
	x := (uint32(len(data)-17) * c0) % 255
	y := 255 - ((c1 + x) % 255)
	return uint16(x)<<8 | uint16(y)
}

// FillDerived recomputes Length and Checksum after the body changed.
func (l *LSA) FillDerived() {
	l.Length = uint16(32 + len(l.Body))
	l.Checksum = 0
	l.Checksum = computeChecksum(l)
}

// VerifyChecksum reports whether the stored checksum matches the payload.
func (l *LSA) VerifyChecksum() bool { return computeChecksum(l) == l.Checksum }

// Marshal encodes the advertisement including its current Age field.
func (l *LSA) Marshal() []byte {
	b := l.wire()
	binary.BigEndian.PutUint16(b[0:], l.Age)
	binary.BigEndian.PutUint16(b[16:], l.Checksum)
	return b
}

// UnmarshalLSA decodes and validates one advertisement.
func UnmarshalLSA(b []byte) (*LSA, error) {
	if len(b) < 32 {
		return nil, fmt.Errorf("lsa: short buffer %d", len(b))
	}
	l := &LSA{
		Age:     binary.BigEndian.Uint16(b[0:]),
		Options: b[2],
		Type:    LSAType(b[3]),
		ID:      binary.BigEndian.Uint32(b[4:]),
		AdvRtr:  binary.BigEndian.Uint32(b[8:]),
		Seq:     binary.BigEndian.Uint32(b[12:]),
		Length:  binary.BigEndian.Uint16(b[18:]),
	}
	if int(l.Length) < 32 || int(l.Length) > len(b) {
		return nil, fmt.Errorf("lsa: bad length %d", l.Length)
	}
	l.Checksum = binary.BigEndian.Uint16(b[16:])
	l.Addr = binary.BigEndian.Uint32(b[20:])
	l.Count = binary.BigEndian.Uint32(b[24:])
	l.Flags = b[28]
	l.Body = append([]byte(nil), b[32:l.Length]...)
	if uint32(len(l.Body)) != l.Count {
		return nil, fmt.Errorf("lsa: body %d != count %d", len(l.Body), l.Count)
	}
	if !l.VerifyChecksum() {
		return nil, fmt.Errorf("lsa: checksum mismatch")
	}
	return l, nil
}

// ---- Builders -------------------------------------------------------------

// RouterLink is one link description in a type 1 advertisement.
type RouterLink struct {
	ID     uint32
	Data   uint32
	Type   uint8 // 1 point-to-point, 2 transit, 3 stub, 4 virtual
	Metric uint16
}

const (
	LinkP2P     uint8 = 1
	LinkTransit uint8 = 2
	LinkStub    uint8 = 3
	LinkVirtual uint8 = 4
)

// BuildRouterLSA creates a type 1 LSA.
func BuildRouterLSA(rtr, area uint32, opts, flags uint8, seq uint32, links []RouterLink) *LSA {
	l := newLSA(LSARouter, rtr, rtr, opts)
	l.Seq = seq
	l.Addr = area
	l.Flags = flags
	l.Count = uint32(len(links) * 12)
	body := make([]byte, 0, len(links)*12)
	for _, ln := range links {
		var e [12]byte
		binary.BigEndian.PutUint32(e[0:], ln.ID)
		binary.BigEndian.PutUint32(e[4:], ln.Data)
		e[8] = ln.Type
		binary.BigEndian.PutUint16(e[10:], ln.Metric)
		body = append(body, e[:]...)
	}
	l.Body = body
	l.FillDerived()
	return l
}

// DecodeRouterLinks parses the link list of a type 1 LSA.
func DecodeRouterLinks(body []byte) []RouterLink {
	var out []RouterLink
	for len(body) >= 12 {
		out = append(out, RouterLink{
			ID:     binary.BigEndian.Uint32(body[0:]),
			Data:   binary.BigEndian.Uint32(body[4:]),
			Type:   body[8],
			Metric: binary.BigEndian.Uint16(body[10:]),
		})
		body = body[12:]
	}
	return out
}

// Prefix is a network/mask pair used by summary and external advertisements.
type Prefix struct {
	Network uint32
	Mask    uint32
	Metric  uint32
	Fwd     uint32
}

func (p Prefix) Bits() int { return maskBits(p.Mask) }

func (p Prefix) String() string { return fmt.Sprintf("%s/%d", u32ip(p.Network), p.Bits()) }

// BuildSummaryLSA creates a type 3 or type 4 LSA carrying one prefix.
func BuildSummaryLSA(typ LSAType, id, adv uint32, seq uint32, opts uint8, p Prefix) *LSA {
	l := newLSA(typ, id, adv, opts)
	l.Seq = seq
	l.Count = 12
	body := make([]byte, 12)
	binary.BigEndian.PutUint32(body[0:], p.Network)
	binary.BigEndian.PutUint32(body[4:], p.Mask)
	binary.BigEndian.PutUint32(body[8:], p.Metric&LSInfinity)
	l.Body = body
	l.FillDerived()
	return l
}

// BuildExternalLSA creates a type 5 LSA carrying one prefix.
func BuildExternalLSA(id, adv uint32, seq uint32, p Prefix) *LSA {
	l := newLSA(LSAASExternal, id, adv, OptE)
	l.Seq = seq
	l.Count = 16
	body := make([]byte, 16)
	binary.BigEndian.PutUint32(body[0:], p.Network)
	binary.BigEndian.PutUint32(body[4:], p.Mask)
	binary.BigEndian.PutUint32(body[8:], p.Metric&LSInfinity)
	binary.BigEndian.PutUint32(body[12:], p.Fwd)
	l.Body = body
	l.FillDerived()
	return l
}

func newLSA(t LSAType, id, adv uint32, opts uint8) *LSA {
	return &LSA{Type: t, ID: id, AdvRtr: adv, Options: opts, Seq: InitialSeqNum}
}

// DecodePrefixes parses summary (12-byte) or external (16-byte) entries.
func DecodePrefixes(t LSAType, body []byte) []Prefix {
	var out []Prefix
	sz := 12
	if t == LSAASExternal || t == LSANSSA {
		sz = 16
	}
	for len(body) >= sz {
		p := Prefix{
			Network: binary.BigEndian.Uint32(body[0:]),
			Mask:    binary.BigEndian.Uint32(body[4:]),
			Metric:  binary.BigEndian.Uint32(body[8:]),
		}
		if sz == 16 {
			p.Fwd = binary.BigEndian.Uint32(body[12:])
		}
		out = append(out, p)
		body = body[sz:]
	}
	return out
}

// AttachedRouters decodes a type 2 network LSA body.
func AttachedRouters(body []byte) []uint32 {
	var out []uint32
	for len(body) >= 4 {
		out = append(out, binary.BigEndian.Uint32(body[0:]))
		body = body[4:]
	}
	return out
}

// ---- Sequence and recency -------------------------------------------------

func seqGT(a, b uint32) bool { return int32(a-b) > 0 }

// LSACompare implements RFC 2328 section 13.1. Negative means a is older,
// zero means same instance, positive means a is more recent.
func LSACompare(a, b *LSA) int {
	if a.Type != b.Type || a.ID != b.ID || a.AdvRtr != b.AdvRtr {
		panic("LSACompare: keys differ")
	}
	if a.Seq != b.Seq {
		if seqGT(a.Seq, b.Seq) {
			return 1
		}
		return -1
	}
	aa, ba := int(a.Age), int(b.Age)
	// MaxAge dominates regardless of checksum: a flushed instance is the most
	// recent form the advertisement can take.
	if aa == int(MaxAge) && ba != int(MaxAge) {
		return 1
	}
	if ba == int(MaxAge) && aa != int(MaxAge) {
		return -1
	}
	if a.Checksum == b.Checksum {
		// Same instance. The one with the smaller LS age is more recent, but
		// only when the difference exceeds MaxAgeDiff; otherwise they are
		// treated as identical (RFC 2328 section 13.1).
		if aa-ba > int(MaxAgeDiff) {
			return -1 // a is older
		}
		if ba-aa > int(MaxAgeDiff) {
			return 1 // a is younger
		}
		return 0
	}
	if aa == int(MaxAge) && ba != int(MaxAge) {
		return 1
	}
	if ba == int(MaxAge) && aa != int(MaxAge) {
		return -1
	}
	if aa-ba > int(MaxAgeDiff) {
		return 1
	}
	if ba-aa > int(MaxAgeDiff) {
		return -1
	}
	if a.Checksum > b.Checksum {
		return 1
	}
	return -1
}

// ---- Address helpers ------------------------------------------------------

// IP renders a router ID or address in dotted form.
func IP(v uint32) string { return u32ip(v) }

func u32ip(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func ipToU32(s string) uint32 {
	var a, b, c, d uint32
	fmt.Sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d)
	return a<<24 | b<<16 | c<<8 | d
}

func maskBits(m uint32) int {
	n := 0
	for i := 31; i >= 0; i-- {
		if m&(1<<uint(i)) == 0 {
			break
		}
		n++
	}
	return n
}

func prefixMask(bits int) uint32 {
	if bits <= 0 {
		return 0
	}
	if bits >= 32 {
		return 0xffffffff
	}
	return ^uint32(0) << uint(32-bits)
}

// PrefixOverlap reports whether p contains q.
func PrefixOverlap(p, q Prefix) bool {
	return p.Network&p.Mask == q.Network&p.Mask && maskBits(q.Mask) >= maskBits(p.Mask)
}

// PrefixName renders a prefix for logs and the page.
func PrefixName(net, mask uint32) string { return pfx(net, mask) }
