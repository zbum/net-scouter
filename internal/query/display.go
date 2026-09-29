package query

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// FlowDisplayOptions controls table byte units and ordering in all output formats.
type FlowDisplayOptions struct {
	ByteUnit string
	SortBy   string
}

func (o FlowDisplayOptions) Validate() error {
	switch o.ByteUnit {
	case "", "k", "m", "h":
	default:
		return fmt.Errorf("byte unit must be k, m, or h")
	}
	switch strings.ToLower(o.SortBy) {
	case "", "p", "packet", "packets", "b", "byte", "bytes", "c", "connection", "connections":
		return nil
	default:
		return fmt.Errorf("sort-by must be packets (p), bytes (b), or connections (c)")
	}
}

func sortFlows(result FlowsResult, sortBy string) FlowsResult {
	if sortBy == "" {
		return result
	}
	result.Records = slices.Clone(result.Records)
	sortBy = strings.ToLower(sortBy)
	slices.SortStableFunc(result.Records, func(a, b FlowView) int {
		switch sortBy {
		case "p", "packet", "packets":
			return cmp.Compare(b.Packets, a.Packets)
		case "b", "byte", "bytes":
			return cmp.Compare(b.Bytes, a.Bytes)
		default:
			aKnown := a.Protocol == 6 && a.Connections != nil
			bKnown := b.Protocol == 6 && b.Connections != nil
			if aKnown != bKnown {
				if aKnown {
					return -1
				}
				return 1
			}
			if !aKnown {
				return 0
			}
			return cmp.Compare(*b.Connections, *a.Connections)
		}
	})
	return result
}

func formatBytes(value uint64, unit string) string {
	switch unit {
	case "k":
		return fmt.Sprintf("%.2f KiB", float64(value)/1024)
	case "m":
		return fmt.Sprintf("%.2f MiB", float64(value)/(1024*1024))
	case "h":
		if value < 1024 {
			return strconv.FormatUint(value, 10) + " B"
		}
		scaled := float64(value)
		units := [...]string{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
		i := 0
		for scaled >= 1024 && i < len(units)-1 {
			scaled /= 1024
			i++
		}
		return fmt.Sprintf("%.2f %s", scaled, units[i])
	default:
		return strconv.FormatUint(value, 10)
	}
}
