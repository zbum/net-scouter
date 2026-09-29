package query

import (
	"encoding/json"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/zbum/net-scouter/internal/flow"
)

func TestFlowByteUnits(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		value uint64
		unit  string
		want  string
	}{
		{0, "", "0"}, {math.MaxUint64, "", "18446744073709551615"},
		{1536, "k", "1.50 KiB"}, {1572864, "m", "1.50 MiB"},
		{0, "k", "0.00 KiB"}, {0, "m", "0.00 MiB"},
		{0, "h", "0 B"}, {1023, "h", "1023 B"}, {1024, "h", "1.00 KiB"},
		{1536, "h", "1.50 KiB"}, {1 << 20, "h", "1.00 MiB"},
		{1 << 30, "h", "1.00 GiB"}, {1 << 40, "h", "1.00 TiB"},
		{1 << 50, "h", "1.00 PiB"}, {1 << 60, "h", "1.00 EiB"},
		{math.MaxUint64, "h", "16.00 EiB"},
	} {
		if got := formatBytes(tc.value, tc.unit); got != tc.want {
			t.Errorf("formatBytes(%d, %q) = %q, want %q", tc.value, tc.unit, got, tc.want)
		}
		result := FlowsResult{Records: []FlowView{{Bytes: tc.value}}}
		got, err := FormatFlowsWithOptions(result, "table", FlowDisplayOptions{ByteUnit: tc.unit})
		if err != nil || !strings.Contains(got, tc.want) {
			t.Errorf("table unit %q: %q, %v", tc.unit, got, err)
		}
	}
}

func TestFlowSortDescendingAndStableWithoutChangingInput(t *testing.T) {
	t.Parallel()
	result := FlowsResult{Records: []FlowView{
		{SrcIP: "a", Packets: 2, Bytes: 1000, Protocol: 6, Connections: new(uint64(0))},
		{SrcIP: "b", Packets: math.MaxUint64, Bytes: 900, Protocol: 17},
		{SrcIP: "c", Packets: 2, Bytes: 999, Protocol: 6, Connections: new(uint64(math.MaxUint64))},
		{SrcIP: "d", Packets: 1, Bytes: 1000, Protocol: 6},
	}}
	for i := range result.Records {
		result.Records[i].Direction = flow.DirectionEgress
	}
	for _, tc := range []struct {
		keys []string
		want []string
	}{
		{[]string{""}, []string{"a", "b", "c", "d"}},
		{[]string{"p", "P", "packet", "packets", "PACKET", "PACKETS"}, []string{"b", "a", "c", "d"}},
		{[]string{"b", "B", "byte", "bytes", "BYTE", "BYTES"}, []string{"a", "d", "c", "b"}},
		{[]string{"c", "C", "connection", "connections", "CONNECTION", "CONNECTIONS"}, []string{"c", "a", "b", "d"}},
	} {
		for _, key := range tc.keys {
			for _, format := range []string{"table", "json", "jsonl"} {
				body, err := FormatFlowsWithOptions(result, format, FlowDisplayOptions{SortBy: key, ByteUnit: "k"})
				if err != nil {
					t.Fatal(err)
				}
				var got []string
				switch format {
				case "json":
					var decoded FlowsResult
					if err := json.Unmarshal([]byte(body), &decoded); err != nil {
						t.Fatal(err)
					}
					for _, row := range decoded.Records {
						got = append(got, row.SrcIP)
					}
				case "jsonl":
					for i, line := range strings.Split(strings.TrimSpace(body), "\n") {
						if i == 0 {
							continue
						}
						var row FlowView
						if err := json.Unmarshal([]byte(line), &row); err != nil {
							t.Fatal(err)
						}
						got = append(got, row.SrcIP)
					}
				case "table":
					for _, line := range strings.Split(strings.TrimSpace(body), "\n")[3:] {
						got = append(got, strings.Fields(line)[0])
					}
				}
				if !slices.Equal(got, tc.want) {
					t.Errorf("sort %q (%s) = %v, want %v", key, format, got, tc.want)
				}
			}
		}
	}
	for i, want := range []string{"a", "b", "c", "d"} {
		if result.Records[i].SrcIP != want {
			t.Fatal("formatting reordered input records")
		}
	}
}

func TestFlowUnitsPreserveJSONCounters(t *testing.T) {
	t.Parallel()
	result := FlowsResult{Records: []FlowView{{Bytes: math.MaxUint64, Packets: 7, Connections: new(uint64(3))}}}
	for _, format := range []string{"json", "jsonl"} {
		want, err := FormatFlows(result, format)
		if err != nil {
			t.Fatal(err)
		}
		for _, unit := range []string{"k", "m", "h"} {
			got, err := FormatFlowsWithOptions(result, format, FlowDisplayOptions{ByteUnit: unit})
			if err != nil || got != want {
				t.Errorf("%s with unit %s changed counters: %s (%v)", format, unit, got, err)
			}
		}
	}
}

func TestFlowDisplayRejectsInvalidOptions(t *testing.T) {
	t.Parallel()
	for _, options := range []FlowDisplayOptions{{ByteUnit: "g"}, {SortBy: "size"}} {
		if _, err := FormatFlowsWithOptions(FlowsResult{}, "table", options); err == nil {
			t.Errorf("accepted invalid options %+v", options)
		}
	}
}
