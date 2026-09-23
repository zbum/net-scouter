package flow

// ACLRecord is the normalized view intended for firewall/ACL analysis.
// Client ephemeral ports are deliberately not part of the initial ACL identity.
type ACLRecord struct {
	Source      string    `json:"source"`
	Destination string    `json:"destination"`
	Protocol    uint8     `json:"protocol"`
	Port        uint16    `json:"port,omitempty"`
	Direction   Direction `json:"direction"`
}

func NormalizeForACL(r Record) ACLRecord {
	return ACLRecord{
		Source:      r.SrcIP.String(),
		Destination: r.DstIP.String(),
		Protocol:    r.Protocol,
		Port:        r.DstPort,
		Direction:   r.Direction,
	}
}
