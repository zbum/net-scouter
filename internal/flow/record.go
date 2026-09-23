package flow

import (
	"fmt"
	"net/netip"
	"time"
)

type Direction uint8

const (
	DirectionIngress Direction = iota + 1
	DirectionEgress
)

func (d Direction) MarshalJSON() ([]byte, error) {
	if d == DirectionIngress {
		return []byte(`"ingress"`), nil
	}
	if d == DirectionEgress {
		return []byte(`"egress"`), nil
	}
	return []byte(fmt.Sprintf(`"unknown(%d)"`, d)), nil
}

type Record struct {
	SrcIP       netip.Addr `json:"src"`
	DstIP       netip.Addr `json:"dst"`
	SrcPort     uint16     `json:"srcPort,omitempty"`
	DstPort     uint16     `json:"dstPort,omitempty"`
	Protocol    uint8      `json:"protocol"`
	Direction   Direction  `json:"direction"`
	FirstSeen   time.Time  `json:"firstSeen"`
	LastSeen    time.Time  `json:"lastSeen"`
	Packets     uint64     `json:"packets"`
	Bytes       uint64     `json:"bytes"`
	Connections uint64     `json:"connections,omitempty"`
}
