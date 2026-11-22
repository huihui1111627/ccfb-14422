package core

import (
	"fmt"
	"hash/fnv"
	"sort"
)

// RouterID identifies a router (also used as its loopback address).
type RouterID uint32

// AreaID identifies an OSPF area. 0 is the backbone.
type AreaID uint32

const Backbone AreaID = 0

// LSA types.
const (
	LSARouter   uint8 = 1
	LSASummary  uint8 = 3
	LSAExternal uint8 = 5
)

// Router-LSA link types.
const (
	LinkP2P     uint8 = 1
	LinkStub    uint8 = 3
	LinkVirtual uint8 = 4
)

// Router-LSA option flags.
const (
	FlagB uint8 = 1 << 0 // area border router
	FlagE uint8 = 1 << 1 // AS boundary router
	FlagV uint8 = 1 << 2 // virtual link endpoint
)

// Prefix is an IPv4 prefix.
type Prefix struct {
	Addr uint32
	Len  uint8
}

func (p Prefix) String() string {
	return fmt.Sprintf("%s/%d", ipStr(p.Addr), p.Len)
}

func ipStr(a uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", a>>24&0xff, a>>16&0xff, a>>8&0xff, a&0xff)
}

// IDStr renders a router id in dotted-quad form.
func IDStr(id RouterID) string { return ipStr(uint32(id)) }

// LSAKey identifies an LSA.
type LSAKey struct {
	Type uint8
	LSID uint32
	Adv  RouterID
}

func (k LSAKey) String() string {
	t := map[uint8]string{LSARouter: "RTR", LSASummary: "SUM", LSAExternal: "EXT"}[k.Type]
	return fmt.Sprintf("%s|%s|%s", t, ipStr(k.LSID), IDStr(k.Adv))
}

// RouterLink is one link entry inside a Router-LSA.
type RouterLink struct {
	Type   uint8  // LinkP2P / LinkStub / LinkVirtual
	ID     uint32 // neighbor router id, or stub network address
	Data   uint32 // stub mask, unused otherwise
	Metric int
}

// RouterLSABody is the body of a Router-LSA.
type RouterLSABody struct {
	Flags uint8
	Links []RouterLink
}

// SummaryLSABody is the body of a type-3 summary LSA.
type SummaryLSABody struct {
	Prefix Prefix
	Metric int
}

// ExternalLSABody is the body of a type-5 external LSA (always E2 here).
type ExternalLSABody struct {
	Prefix Prefix
	Metric int
}

// LSA is one link-state advertisement instance.
type LSA struct {
	Key         LSAKey
	Seq         uint32
	Cksum       uint32
	BaseAge     uint16 // age when installed
	InstalledAt int64  // world time of install
	Body        interface{}
	Self        bool // self-originated
}

// Age returns the LSA age at the given world time.
func (l *LSA) Age(now int64) int64 {
	return int64(l.BaseAge) + (now - l.InstalledAt)
}

// BodyOf returns the typed body.
func (l *LSA) RouterBody() *RouterLSABody     { return l.Body.(*RouterLSABody) }
func (l *LSA) SummaryBody() *SummaryLSABody   { return l.Body.(*SummaryLSABody) }
func (l *LSA) ExternalBody() *ExternalLSABody { return l.Body.(*ExternalLSABody) }

// checksum computes a deterministic content checksum.
func (l *LSA) checksum() uint32 {
	h := fnv.New32a()
	var b [8]byte
	put := func(v uint32) {
		b[0] = byte(v >> 24)
		b[1] = byte(v >> 16)
		b[2] = byte(v >> 8)
		b[3] = byte(v)
		h.Write(b[:4])
	}
	put(uint32(l.Key.Type))
	put(l.Key.LSID)
	put(uint32(l.Key.Adv))
	put(l.Seq)
	switch bd := l.Body.(type) {
	case *RouterLSABody:
		put(uint32(bd.Flags))
		put(uint32(len(bd.Links)))
		for _, lk := range bd.Links {
			put(uint32(lk.Type))
			put(lk.ID)
			put(lk.Data)
			put(uint32(lk.Metric))
		}
	case *SummaryLSABody:
		put(bd.Prefix.Addr)
		put(uint32(bd.Prefix.Len))
		put(uint32(bd.Metric))
	case *ExternalLSABody:
		put(bd.Prefix.Addr)
		put(uint32(bd.Prefix.Len))
		put(uint32(bd.Metric))
	}
	return h.Sum32()
}

// NewerThan reports whether l is a more recent instance than o,
// per RFC 2328 section 13.1: sequence number, then checksum, then age.
func (l *LSA) NewerThan(o *LSA, now int64, maxAgeDiff int64, maxAge int64) bool {
	if l.Seq != o.Seq {
		return l.Seq > o.Seq
	}
	if l.Cksum != o.Cksum {
		return l.Cksum > o.Cksum
	}
	la, oa := l.Age(now), o.Age(now)
	lMax, oMax := la >= maxAge, oa >= maxAge
	if lMax != oMax {
		return lMax
	}
	d := la - oa
	if d < 0 {
		d = -d
	}
	if d > maxAgeDiff {
		return la < oa
	}
	return false
}

// SameInstance reports whether two LSAs are the same instance.
func (l *LSA) SameInstance(o *LSA, now int64, maxAgeDiff int64) bool {
	if l.Seq != o.Seq || l.Cksum != o.Cksum {
		return false
	}
	d := l.Age(now) - o.Age(now)
	if d < 0 {
		d = -d
	}
	return d <= maxAgeDiff
}

func sortedKeys(m map[LSAKey]*LSA) []LSAKey {
	ks := make([]LSAKey, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool {
		a, b := ks[i], ks[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.LSID != b.LSID {
			return a.LSID < b.LSID
		}
		return a.Adv < b.Adv
	})
	return ks
}

// Config holds tunable protocol timers (in world ticks).
type Config struct {
	HelloInterval int64
	DeadInterval  int64
	RxmtInterval  int64
	SpfDelay      int64
	RefreshTime   int64 // self-originated LSA refresh
	MaxAge        int64
	MaxAgeDiff    int64
	StableWindow  int64 // quiescence detection window for the harness
	DDChunk       int   // LSA headers per DD packet
	Verify        bool  // cross-check iSPF against full SPF on every change
}

// DefaultConfig returns the default timer configuration.
func DefaultConfig() Config {
	return Config{
		HelloInterval: 10,
		DeadInterval:  40,
		RxmtInterval:  15,
		SpfDelay:      2,
		RefreshTime:   1800,
		MaxAge:        3600,
		MaxAgeDiff:    900,
		StableWindow:  200,
		DDChunk:       8,
	}
}
