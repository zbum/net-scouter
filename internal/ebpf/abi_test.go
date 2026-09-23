package ebpf

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

func TestFlowABILayoutMatchesC(t *testing.T) {
	t.Parallel()

	key := FlowKey{}
	value := FlowValue{}
	if got := binary.Size(key); got != int(FlowKeySize) {
		t.Fatalf("FlowKey binary size = %d, memory size = %d", got, FlowKeySize)
	}
	if got := unsafe.Offsetof(key.SrcPort); got != 36 {
		t.Errorf("FlowKey.SrcPort offset = %d, want 36", got)
	}
	if got := unsafe.Offsetof(key.DstPort); got != 38 {
		t.Errorf("FlowKey.DstPort offset = %d, want 38", got)
	}
	if got := binary.Size(value); got != int(FlowValueSize) {
		t.Fatalf("FlowValue binary size = %d, memory size = %d", got, FlowValueSize)
	}
	if got := unsafe.Offsetof(value.Connections); got != 32 {
		t.Errorf("FlowValue.Connections offset = %d, want 32", got)
	}
}
