package query

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/example/net-scouter/internal/flow"
)

func PrepareFlows(records []flow.Record, connectionsAvailable bool, abi, detail string) FlowsResult {
	views := make([]FlowView, 0, len(records))
	for _, record := range records {
		views = append(views, NewFlowView(record, connectionsAvailable))
	}
	slices.SortFunc(views, func(a, b FlowView) int {
		if c := b.LastSeen.Compare(a.LastSeen); c != 0 {
			return c
		}
		if c := cmp.Compare(a.SrcIP, b.SrcIP); c != 0 {
			return c
		}
		if c := cmp.Compare(a.DstIP, b.DstIP); c != 0 {
			return c
		}
		if c := cmp.Compare(a.SrcPort, b.SrcPort); c != 0 {
			return c
		}
		if c := cmp.Compare(a.DstPort, b.DstPort); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Protocol, b.Protocol); c != 0 {
			return c
		}
		return cmp.Compare(a.Direction, b.Direction)
	})
	return FlowsResult{
		ConnectionsAvailable: connectionsAvailable,
		ConnectionABI:        abi,
		ConnectionDetail:     detail,
		DurableStorage:       DurableUnavailable,
		Records:              views,
	}
}

func FormatStatus(st Status) string {
	var b strings.Builder
	fmt.Fprintf(&b, "state:                 %s\n", stateText(st))
	fmt.Fprintf(&b, "source:                %s\n", empty(st.Source, "none"))
	if st.Source == "none" {
		fmt.Fprintf(&b, "durable storage:       %s (%s)\n", empty(st.DurableStorage, DurableUnavailable), empty(st.DurableReason, DurableReason))
		fmt.Fprintf(&b, "last error:            %s\n", empty(st.LastError, "(none)"))
		return b.String()
	}
	if st.PID != 0 {
		fmt.Fprintf(&b, "pid:                   %d\n", st.PID)
	}
	fmt.Fprintf(&b, "started:               %s\n", formatTime(st.StartedAt))
	fmt.Fprintf(&b, "last snapshot:         %s\n", formatTime(st.LastSnapshotAt))
	fmt.Fprintf(&b, "interfaces:            %s\n", joinOrNone(st.Interfaces))
	if st.Interval != "" {
		fmt.Fprintf(&b, "interval:              %s\n", st.Interval)
	}
	if st.ObservedFrom.IsZero() {
		fmt.Fprintf(&b, "observed:              (no visible flows)\n")
	} else {
		fmt.Fprintf(&b, "observed:              %s .. %s\n", st.ObservedFrom.Format(time.RFC3339), st.ObservedTo.Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "map entries:           %d / %d\n", st.Map.Entries, st.Map.MaxEntries)
	if st.Map.PossibleLoss {
		fmt.Fprintf(&b, "possible loss:         yes, map is at capacity; new flows can evict existing ones and results may be incomplete\n")
	} else {
		fmt.Fprintf(&b, "possible loss:         no\n")
	}
	if st.Connections.Enabled {
		fmt.Fprintf(&b, "tcp connections:       enabled (trace ABI %s)\n", empty(st.Connections.ABI, "unknown"))
	} else {
		fmt.Fprintf(&b, "tcp connections:       unavailable (%s)\n", empty(st.Connections.Detail, "disabled"))
	}
	fmt.Fprintf(&b, "exclude destinations:  %s\n", joinOrNone(st.Exclude.Destinations))
	fmt.Fprintf(&b, "workload CIDRs:        %s\n", joinOrNone(st.Exclude.WorkloadCIDRs))
	fmt.Fprintf(&b, "durable storage:       %s (%s)\n", empty(st.DurableStorage, DurableUnavailable), empty(st.DurableReason, DurableReason))
	fmt.Fprintf(&b, "last error:            %s\n", empty(st.LastError, "(none)"))
	return b.String()
}

func FilterProtocol(result FlowsResult, protocol string) (FlowsResult, error) {
	var want uint8
	switch protocol {
	case "", "both":
		return result, nil
	case "tcp":
		want = 6
	case "udp":
		want = 17
	default:
		return FlowsResult{}, fmt.Errorf("protocol must be tcp, udp, or both")
	}
	filtered := make([]FlowView, 0, len(result.Records))
	for _, record := range result.Records {
		if record.Protocol == want {
			filtered = append(filtered, record)
		}
	}
	result.Records = filtered
	return result, nil
}

func FilterEstablished(result FlowsResult, includeAttempts bool) FlowsResult {
	if includeAttempts || !result.ConnectionsAvailable {
		return result
	}
	filtered := make([]FlowView, 0, len(result.Records))
	for _, record := range result.Records {
		if record.Protocol == 6 && (record.Connections == nil || *record.Connections == 0) {
			continue
		}
		filtered = append(filtered, record)
	}
	result.Records = filtered
	return result
}

func FormatFlows(result FlowsResult, format string) (string, error) {
	switch format {
	case "table", "":
		return formatTable(result), nil
	case "json":
		body, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return "", err
		}
		return string(body) + "\n", nil
	case "jsonl":
		var b strings.Builder
		enc := json.NewEncoder(&b)
		meta := map[string]any{
			"type":                 "meta",
			"connectionsAvailable": result.ConnectionsAvailable,
			"durableStorage":       result.DurableStorage,
		}
		if result.ConnectionABI != "" {
			meta["connectionABI"] = result.ConnectionABI
		}
		if result.ConnectionDetail != "" {
			meta["connectionDetail"] = result.ConnectionDetail
		}
		if err := enc.Encode(meta); err != nil {
			return "", err
		}
		for _, record := range result.Records {
			row := struct {
				Type string `json:"type"`
				FlowView
			}{Type: "flow", FlowView: record}
			if err := enc.Encode(row); err != nil {
				return "", err
			}
		}
		return b.String(), nil
	default:
		return "", fmt.Errorf("unknown flows format %q", format)
	}
}

func formatTable(result FlowsResult) string {
	var b strings.Builder
	if result.ConnectionsAvailable {
		if result.ConnectionABI != "" {
			fmt.Fprintf(&b, "tcp connections: enabled (trace ABI %s)\n", result.ConnectionABI)
		} else {
			fmt.Fprintf(&b, "tcp connections: enabled\n")
		}
	} else {
		fmt.Fprintf(&b, "tcp connections: unavailable (%s)\n", empty(result.ConnectionDetail, "disabled"))
	}
	fmt.Fprintf(&b, "durable storage: %s\n", empty(result.DurableStorage, DurableUnavailable))
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SRC\tDST\tPROTO\tDIR\tPORT\tFIRST SEEN\tLAST SEEN\tPACKETS\tBYTES\tCONNECTIONS")
	for _, record := range result.Records {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%d\t%d\t%s\n",
			record.SrcIP,
			record.DstIP,
			protocolName(record.Protocol),
			record.Direction.String(),
			record.DstPort,
			record.FirstSeen.Format(time.RFC3339),
			record.LastSeen.Format(time.RFC3339),
			record.Packets,
			record.Bytes,
			connectionCell(record),
		)
	}
	_ = w.Flush()
	return b.String()
}

func connectionCell(record FlowView) string {
	if record.Protocol != 6 {
		return "-"
	}
	if record.Connections == nil {
		return "n/a"
	}
	return strconv.FormatUint(*record.Connections, 10)
}

func protocolName(protocol uint8) string {
	switch protocol {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return strconv.FormatUint(uint64(protocol), 10)
	}
}

func stateText(st Status) string {
	switch {
	case st.Running && st.Live:
		return "running"
	case st.Running:
		return "running (query socket unavailable; showing saved status)"
	case st.Stale:
		return "not running (saved status is stale)"
	default:
		return "not running"
	}
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return "(none)"
	}
	return value.Format(time.RFC3339)
}

func joinOrNone(values []string) string {
	if len(values) == 0 {
		return "(none)"
	}
	return strings.Join(values, ", ")
}

func empty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
