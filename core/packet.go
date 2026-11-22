package core

// Packet types.
const (
	PktHello uint8 = 1
	PktDD    uint8 = 2
	PktLSR   uint8 = 3
	PktLSU   uint8 = 4
	PktLSAck uint8 = 5
)

// DD packet flag bits.
const (
	DDFlagI  uint8 = 1 << 2 // init
	DDFlagM  uint8 = 1 << 1 // more
	DDFlagMS uint8 = 1 << 0 // master/slave
)

// Packet is a union of all OSPF packet payloads.
type Packet struct {
	Type uint8
	Src  RouterID
	Area AreaID

	// Hello
	Seen []RouterID

	// DD
	MTU      int
	Flags    uint8
	DDSeq    uint32
	Heads    []LSAKey // LSA headers (key+seq+cksum+age carried in HeadLSAs)
	HeadLSAs []*LSA

	// LSR
	Requests []LSAKey

	// LSU / LSAck
	LSAs []*LSA
}

func pktTypeName(t uint8) string {
	switch t {
	case PktHello:
		return "Hello"
	case PktDD:
		return "DD"
	case PktLSR:
		return "LSR"
	case PktLSU:
		return "LSU"
	case PktLSAck:
		return "LSAck"
	}
	return "?"
}

// headerOf extracts a lightweight LSA header copy for DD/LSAck packets.
func headerOf(l *LSA, now int64) *LSA {
	cp := *l
	cp.Body = nil
	// carry the current age so the receiver can compare correctly
	cp.BaseAge = uint16(l.Age(now))
	cp.InstalledAt = now
	return &cp
}
