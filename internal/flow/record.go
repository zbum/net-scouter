package flow

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"time"
)

type Direction uint8

const (
	DirectionIngress Direction = iota + 1
	DirectionEgress
)

func (d Direction) String() string {
	if d == DirectionIngress {
		return "ingress"
	}
	if d == DirectionEgress {
		return "egress"
	}
	return fmt.Sprintf("unknown(%d)", d)
}

func (d Direction) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *Direction) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return fmt.Errorf("direction: %w", err)
	}
	switch text {
	case "ingress":
		*d = DirectionIngress
	case "egress":
		*d = DirectionEgress
	default:
		return fmt.Errorf("invalid direction %q", text)
	}
	return nil
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

// CollapseTCPSourcePorts merges TCP rows that differ only by source port.
// UDP keeps its source port. Packet, byte, and connection counters are summed.
func CollapseTCPSourcePorts(records []Record) []Record {
	if len(records) == 1 && records[0].Protocol == 6 {
		record := records[0]
		record.SrcPort = 0
		return []Record{record}
	}
	if len(records) < 2 {
		return records
	}
	type key struct {
		src, dst         netip.Addr
		srcPort, dstPort uint16
		protocol         uint8
		direction        Direction
	}
	order := make([]key, 0, len(records))
	merged := make(map[key]Record, len(records))
	for _, record := range records {
		if record.Protocol == 6 {
			record.SrcPort = 0
		}
		id := key{record.SrcIP, record.DstIP, record.SrcPort, record.DstPort, record.Protocol, record.Direction}
		previous, ok := merged[id]
		if !ok {
			merged[id] = record
			order = append(order, id)
			continue
		}
		if previous.FirstSeen.IsZero() || (!record.FirstSeen.IsZero() && record.FirstSeen.Before(previous.FirstSeen)) {
			previous.FirstSeen = record.FirstSeen
		}
		if record.LastSeen.After(previous.LastSeen) {
			previous.LastSeen = record.LastSeen
		}
		previous.Packets += record.Packets
		previous.Bytes += record.Bytes
		previous.Connections += record.Connections
		merged[id] = previous
	}
	out := make([]Record, 0, len(order))
	for _, id := range order {
		out = append(out, merged[id])
	}
	return out
}
