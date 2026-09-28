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
	EpochNS     uint64     `json:"-"`
}

// ForACL keeps firewall rules and drops the return path.
// Ingress keeps the destination port. Egress keeps the destination port of a
// connection this host opened. Packets this host sends back to a client are removed.
func ForACL(records []Record) []Record {
	return collapseSameKey(forACLRaw(records, false))
}

// ForACLRaw applies return-path selection while preserving source ports for
// per-kernel-entry counter delta accounting.
func ForACLRaw(records []Record) []Record {
	return forACLRaw(records, true)
}

func forACLRaw(records []Record, preserveSourcePort bool) []Record {
	const ephemeral = 32768
	type peer struct {
		src, dst  netip.Addr
		protocol  uint8
		direction Direction
	}
	lowPort := make(map[peer]bool, len(records))
	for _, record := range records {
		if record.DstPort > 0 && record.DstPort < ephemeral {
			lowPort[peer{record.SrcIP, record.DstIP, record.Protocol, record.Direction}] = true
		}
	}
	kept := make([]Record, 0, len(records))
	for _, record := range records {
		if record.Protocol != 6 && record.Protocol != 17 {
			kept = append(kept, record)
			continue
		}
		opposite := DirectionIngress
		if record.Direction == DirectionIngress {
			opposite = DirectionEgress
		}
		returnPath := record.Connections == 0 && record.DstPort >= ephemeral &&
			lowPort[peer{record.DstIP, record.SrcIP, record.Protocol, opposite}]
		if returnPath {
			continue
		}
		if !preserveSourcePort {
			record.SrcPort = 0
		}
		kept = append(kept, record)
	}
	return kept
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
	return collapseSameKey(records)
}

func collapseSameKey(records []Record) []Record {
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
