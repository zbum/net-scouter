package ebpf

import "unsafe"

// FlowKey is the userspace representation of struct flow_key in bpf/flow.h.
// Keep field order and padding synchronized with the kernel ABI.
type FlowKey struct {
	Family    uint8
	Protocol  uint8
	Direction uint8
	Pad       uint8
	SrcAddr   [16]byte
	DstAddr   [16]byte
	SrcPort   uint16
	DstPort   uint16
}

// FlowValue is the userspace representation of struct flow_value in bpf/flow.h.
type FlowValue struct {
	FirstSeenNS uint64
	LastSeenNS  uint64
	Packets     uint64
	Bytes       uint64
	Connections uint64
}

type hostAddressKey struct {
	Family uint8
	Addr   [16]byte
}

const (
	FlowKeySize        = unsafe.Sizeof(FlowKey{})
	FlowValueSize      = unsafe.Sizeof(FlowValue{})
	hostAddressKeySize = unsafe.Sizeof(hostAddressKey{})
)

// These paired declarations fail compilation if either ABI size changes.
var (
	_ [40 - FlowKeySize]byte
	_ [FlowKeySize - 40]byte
	_ [40 - FlowValueSize]byte
	_ [FlowValueSize - 40]byte
	_ [17 - hostAddressKeySize]byte
	_ [hostAddressKeySize - 17]byte
)
