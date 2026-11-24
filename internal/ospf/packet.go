package ospf

import (
	"encoding/binary"
	"fmt"
)

// Packet types.
const (
	PktHello uint8 = 1
	PktDD    uint8 = 2
	PktLSR   uint8 = 3
	PktLSU   uint8 = 4
	PktLSAck uint8 = 5
)

func PktTypeName(t uint8) string {
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
	return fmt.Sprintf("Pkt(%d)", t)
}

// Neighbour states.
type NbrState uint8

const (
	Down NbrState = iota
	Attempt
	Init
	TwoWay
	ExStart
	Exchange
	Loading
	Full
)

func (s NbrState) String() string {
	switch s {
	case Down:
		return "Down"
	case Attempt:
		return "Attempt"
	case Init:
		return "Init"
	case TwoWay:
		return "2-Way"
	case ExStart:
		return "ExStart"
	case Exchange:
		return "Exchange"
	case Loading:
		return "Loading"
	case Full:
		return "Full"
	}
	return "?"
}

// Interface types for OSPF (only point-to-point and broadcast are simulated).
const (
	IfP2P       uint8 = 1
	IfBroadcast uint8 = 2
	IfVirtual   uint8 = 4
)

// Packet is a single encoded OSPF message as it crosses a link.
type Packet struct {
	Type    uint8
	Src     uint32 // source router ID
	Dst     uint32 // destination router ID (per-neighbour delivery on P2P)
	SrcArea uint32
	Body    []byte
	// SrcIP is the interface address the packet was sourced from.
	SrcIP uint32
}

// Marshal encodes the common header plus body.
func (p *Packet) Marshal() []byte {
	b := make([]byte, 16, 16+len(p.Body))
	b[0] = 2 // version
	b[1] = p.Type
	binary.BigEndian.PutUint32(b[4:], p.Src)
	binary.BigEndian.PutUint32(b[8:], p.SrcArea)
	binary.BigEndian.PutUint16(b[14:], uint16(len(p.Body)))
	return append(b, p.Body...)
}

// UnmarshalPacket decodes a packet.
func UnmarshalPacket(b []byte) (*Packet, error) {
	if len(b) < 16 {
		return nil, fmt.Errorf("pkt: short")
	}
	if b[0] != 2 {
		return nil, fmt.Errorf("pkt: version %d", b[0])
	}
	n := int(binary.BigEndian.Uint16(b[14:]))
	if n > len(b)-16 {
		return nil, fmt.Errorf("pkt: truncated body")
	}
	return &Packet{
		Type:    b[1],
		Src:     binary.BigEndian.Uint32(b[4:]),
		SrcArea: binary.BigEndian.Uint32(b[8:]),
		Body:    append([]byte(nil), b[16:16+n]...),
	}, nil
}

// HelloBody is the decoded Hello payload.
type HelloBody struct {
	NetworkMask    uint32
	HelloInterval  uint16
	Options        uint8
	RouterPriority uint8
	DeadInterval   uint16
	DesignatedRtr  uint32
	BackupRtr      uint32
	Neighbours     []uint32
}

// Hello packet size for a P2P link with no neighbours listed yet.
func HelloSize(nbrs int) int { return 16 + 20 + 4*nbrs }

func MarshalHello(h HelloBody) []byte {
	b := make([]byte, 20, 20+4*len(h.Neighbours))
	binary.BigEndian.PutUint32(b[0:], h.NetworkMask)
	binary.BigEndian.PutUint16(b[4:], h.HelloInterval)
	b[6] = h.Options
	b[7] = h.RouterPriority
	binary.BigEndian.PutUint16(b[8:], h.DeadInterval)
	binary.BigEndian.PutUint32(b[12:], h.DesignatedRtr)
	binary.BigEndian.PutUint32(b[16:], h.BackupRtr)
	for _, n := range h.Neighbours {
		var e [4]byte
		binary.BigEndian.PutUint32(e[:], n)
		b = append(b, e[:]...)
	}
	return b
}

func UnmarshalHello(b []byte) (HelloBody, error) {
	var h HelloBody
	if len(b) < 20 {
		return h, fmt.Errorf("hello: short")
	}
	h.NetworkMask = binary.BigEndian.Uint32(b[0:])
	h.HelloInterval = binary.BigEndian.Uint16(b[4:])
	h.Options = b[6]
	h.RouterPriority = b[7]
	h.DeadInterval = binary.BigEndian.Uint16(b[8:])
	h.DesignatedRtr = binary.BigEndian.Uint32(b[12:])
	h.BackupRtr = binary.BigEndian.Uint32(b[16:])
	for i := 20; i+4 <= len(b); i += 4 {
		h.Neighbours = append(h.Neighbours, binary.BigEndian.Uint32(b[i:]))
	}
	return h, nil
}

// DDBody is a Database Description packet.
type DDBody struct {
	MTU        uint16
	Options    uint8
	I, M, MS   bool
	DDSeq      uint32
	LSAHeaders []LSAHead
}

// LSAHead is the 20-byte LSA header carried in DD and LSAck packets.
type LSAHead struct {
	Age      uint16
	Options  uint8
	Type     LSAType
	ID       uint32
	AdvRtr   uint32
	Seq      uint32
	Checksum uint16
	Length   uint16
}

func (h LSAHead) Key() LSAKey { return LSAKey{h.Type, h.ID, h.AdvRtr} }

func (h LSAHead) Marshal() []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:], h.Age)
	b[2] = h.Options
	b[3] = byte(h.Type)
	binary.BigEndian.PutUint32(b[4:], h.ID)
	binary.BigEndian.PutUint32(b[8:], h.AdvRtr)
	binary.BigEndian.PutUint32(b[12:], h.Seq)
	binary.BigEndian.PutUint16(b[16:], h.Checksum)
	binary.BigEndian.PutUint16(b[18:], h.Length)
	return b
}

func ParseLSAHead(b []byte) (LSAHead, error) {
	if len(b) < 20 {
		return LSAHead{}, fmt.Errorf("head: short")
	}
	return LSAHead{
		Age:      binary.BigEndian.Uint16(b[0:]),
		Options:  b[2],
		Type:     LSAType(b[3]),
		ID:       binary.BigEndian.Uint32(b[4:]),
		AdvRtr:   binary.BigEndian.Uint32(b[8:]),
		Seq:      binary.BigEndian.Uint32(b[12:]),
		Checksum: binary.BigEndian.Uint16(b[16:]),
		Length:   binary.BigEndian.Uint16(b[18:]),
	}, nil
}

func HeadOf(l *LSA) LSAHead {
	return LSAHead{Age: l.Age, Options: l.Options, Type: l.Type, ID: l.ID,
		AdvRtr: l.AdvRtr, Seq: l.Seq, Checksum: l.Checksum, Length: l.Length}
}

// DDHeaderSize is the fixed part before the LSA headers.
const DDHeaderSize = 8

func MarshalDD(d DDBody, heads []LSAHead) []byte {
	b := make([]byte, DDHeaderSize, DDHeaderSize+20*len(heads))
	binary.BigEndian.PutUint16(b[0:], d.MTU)
	b[2] = d.Options
	if d.I {
		b[3] |= 0x04
	}
	if d.M {
		b[3] |= 0x02
	}
	if d.MS {
		b[3] |= 0x01
	}
	binary.BigEndian.PutUint32(b[4:], d.DDSeq)
	for _, h := range heads {
		b = append(b, h.Marshal()...)
	}
	return b
}

func UnmarshalDD(b []byte) (DDBody, []LSAHead, error) {
	var d DDBody
	if len(b) < DDHeaderSize {
		return d, nil, fmt.Errorf("dd: short")
	}
	d.MTU = binary.BigEndian.Uint16(b[0:])
	d.Options = b[2]
	d.I = b[3]&0x04 != 0
	d.M = b[3]&0x02 != 0
	d.MS = b[3]&0x01 != 0
	d.DDSeq = binary.BigEndian.Uint32(b[4:])
	var heads []LSAHead
	rest := b[DDHeaderSize:]
	for len(rest) >= 20 {
		h, err := ParseLSAHead(rest)
		if err != nil {
			return d, heads, err
		}
		heads = append(heads, h)
		rest = rest[20:]
	}
	return d, heads, nil
}

// LSRBody is a Link State Request: a list of keys.
func MarshalLSR(keys []LSAKey) []byte {
	b := make([]byte, 0, 12*len(keys))
	for _, k := range keys {
		var e [12]byte
		binary.BigEndian.PutUint32(e[0:], uint32(k.Type))
		binary.BigEndian.PutUint32(e[4:], k.ID)
		binary.BigEndian.PutUint32(e[8:], k.AdvRtr)
		b = append(b, e[:]...)
	}
	return b
}

func UnmarshalLSR(b []byte) []LSAKey {
	var out []LSAKey
	for len(b) >= 12 {
		out = append(out, LSAKey{
			Type:   LSAType(binary.BigEndian.Uint32(b[0:])),
			ID:     binary.BigEndian.Uint32(b[4:]),
			AdvRtr: binary.BigEndian.Uint32(b[8:]),
		})
		b = b[12:]
	}
	return out
}

// LSUBody is a Link State Update: a list of full advertisements.
func MarshalLSU(lsas []*LSA) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(len(lsas)))
	for _, l := range lsas {
		b = append(b, l.Marshal()...)
	}
	return b
}

func UnmarshalLSU(b []byte) ([]*LSA, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("lsu: short")
	}
	n := int(binary.BigEndian.Uint32(b))
	rest := b[4:]
	var out []*LSA
	for i := 0; i < n; i++ {
		if len(rest) < 20 {
			return out, fmt.Errorf("lsu: truncated lsa %d", i)
		}
		ln := int(binary.BigEndian.Uint16(rest[18:]))
		if ln < 28 || ln > len(rest) {
			return out, fmt.Errorf("lsu: bad lsa length %d", ln)
		}
		l, err := UnmarshalLSA(rest[:ln])
		if err != nil {
			return out, err
		}
		out = append(out, l)
		rest = rest[ln:]
	}
	return out, nil
}

// MarshalLSAck encodes a set of LSA headers.
func MarshalLSAck(heads []LSAHead) []byte {
	b := make([]byte, 0, 20*len(heads))
	for _, h := range heads {
		b = append(b, h.Marshal()...)
	}
	return b
}

func UnmarshalLSAck(b []byte) []LSAHead {
	var out []LSAHead
	for len(b) >= 20 {
		h, err := ParseLSAHead(b)
		if err == nil {
			out = append(out, h)
		}
		b = b[20:]
	}
	return out
}

// PacketSize estimates the wire size of a packet given its body length.
func PacketSize(pktType uint8, bodyLen int) int { return 16 + bodyLen }
