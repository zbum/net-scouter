package ebpf

import (
	"testing"
	"time"
)

func TestDecodeRecordConvertsIPv4AndMonotonicTime(t *testing.T) {
	t.Parallel()
	k := FlowKey{Family: 2, Protocol: 6, Direction: 1, SrcAddr: [16]byte{10, 0, 0, 1}, DstAddr: [16]byte{10, 0, 0, 2}, SrcPort: 123, DstPort: 443}
	v := FlowValue{FirstSeenNS: uint64(time.Second), LastSeenNS: uint64(2 * time.Second), Connections: 2}
	r, err := DecodeRecord(k, v, time.Unix(100, 0), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if r.SrcIP.String() != "10.0.0.1" || !r.FirstSeen.Equal(time.Unix(91, 0)) || r.Connections != 2 {
		t.Fatalf("record: %+v", r)
	}
}

func TestDecodeRecordRejectsInvalidABIValues(t *testing.T) {
	t.Parallel()
	if _, err := DecodeRecord(FlowKey{Family: 2, Protocol: 1, Direction: 1}, FlowValue{}, time.Time{}, 0); err == nil {
		t.Fatal("expected protocol error")
	}
}
