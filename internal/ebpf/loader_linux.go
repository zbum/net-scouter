//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/example/net-scouter/internal/flow"
)

const (
	filterPriority = 49152
	ingressHandle  = 0x1
	egressHandle   = 0x2
)

type Loader struct {
	collection     *cebpf.Collection
	flows          *cebpf.Map
	trace          link.Link
	traceAttempted bool
	connEnabled    bool
	connABI        string
	filters        []netlink.Filter
}

func Open(objectPath string, maxFlows uint32) (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}
	spec, err := cebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return nil, fmt.Errorf("read BPF object: %w", err)
	}
	m, ok := spec.Maps["flows"]
	if !ok {
		return nil, errors.New("BPF object has no flows map")
	}
	if m.Type != cebpf.LRUHash || m.KeySize != uint32(FlowKeySize) || m.ValueSize != uint32(FlowValueSize) {
		return nil, fmt.Errorf("flows map ABI mismatch: type=%s key=%d value=%d", m.Type, m.KeySize, m.ValueSize)
	}
	m.MaxEntries = maxFlows
	for _, name := range []string{"observe_ingress", "observe_egress", "tcp_conn_u8", "tcp_conn_u16"} {
		if spec.Programs[name] == nil {
			return nil, fmt.Errorf("BPF object has no program %q", name)
		}
	}
	c, err := cebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load BPF collection: %w", err)
	}
	return &Loader{collection: c, flows: c.Maps["flows"]}, nil
}

func (l *Loader) SetCapture(ipv4, ipv6, tcp, udp bool) error {
	m := l.collection.Maps["capture_cfg"]
	if m == nil {
		return errors.New("BPF object has no capture_cfg map")
	}
	value := captureConfig{boolByte(ipv4), boolByte(ipv6), boolByte(tcp), boolByte(udp)}
	if err := m.Put(uint32(0), value); err != nil {
		return fmt.Errorf("set capture config: %w", err)
	}
	return nil
}

type captureConfig struct {
	IPv4 uint8
	IPv6 uint8
	TCP  uint8
	UDP  uint8
}

func boolByte(value bool) uint8 {
	if value {
		return 1
	}
	return 0
}

func (l *Loader) AttachTracepoint() (bool, error) {
	if l.traceAttempted {
		return false, errors.New("tracepoint attachment already attempted")
	}
	l.traceAttempted = true
	abi, err := probeTraceFormat(traceFormatPaths, func(path string) (io.ReadCloser, error) { return os.Open(path) })
	if err != nil {
		return false, err
	}
	var p *cebpf.Program
	abiName := ""
	if abi == TraceProtocolU8 {
		p = l.collection.Programs["tcp_conn_u8"]
		abiName = "4.18"
	}
	if abi == TraceProtocolU16 {
		p = l.collection.Programs["tcp_conn_u16"]
		abiName = "5.15"
	}
	if p == nil {
		l.connEnabled = false
		l.connABI = ""
		return false, nil
	}
	l.trace, err = link.Tracepoint("sock", "inet_sock_set_state", p, nil)
	if err != nil {
		return false, fmt.Errorf("attach TCP state tracepoint: %w", err)
	}
	l.connEnabled = true
	l.connABI = abiName
	return true, nil
}

func (l *Loader) ConnectionCounting() (bool, string) {
	return l.connEnabled, l.connABI
}

func (l *Loader) AttachTC(names []string, allowVirtual bool) error {
	for _, name := range names {
		device, err := netlink.LinkByName(name)
		if err != nil {
			return l.attachFailure(fmt.Errorf("interface %s: %w", name, err))
		}
		if !allowVirtual && !allowedLink(device) {
			return l.attachFailure(fmt.Errorf("interface %s type %q is not an allowed physical/bond/VLAN uplink", name, device.Type()))
		}
		q := &netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{LinkIndex: device.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT}}
		if err := netlink.QdiscAdd(q); err != nil && !errors.Is(err, unix.EEXIST) {
			return l.attachFailure(fmt.Errorf("ensure clsact on %s: %w", name, err))
		}
		for _, d := range []struct {
			parent, handle uint32
			program, label string
		}{
			{netlink.HANDLE_MIN_INGRESS, ingressHandle, "observe_ingress", "net-scouter-ingress"},
			{netlink.HANDLE_MIN_EGRESS, egressHandle, "observe_egress", "net-scouter-egress"},
		} {
			existing, err := netlink.FilterList(device, d.parent)
			if err != nil {
				return l.attachFailure(err)
			}
			for _, f := range existing {
				a := f.Attrs()
				if a.Priority == filterPriority || a.Handle == d.handle {
					return l.attachFailure(fmt.Errorf("TC ownership collision on %s parent %#x", name, d.parent))
				}
			}
			filter := &netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{LinkIndex: device.Attrs().Index, Parent: d.parent, Handle: d.handle, Priority: filterPriority, Protocol: unix.ETH_P_ALL}, Fd: l.collection.Programs[d.program].FD(), Name: d.label, DirectAction: true}
			if err := netlink.FilterAdd(filter); err != nil {
				return l.attachFailure(fmt.Errorf("attach %s to %s: %w", d.program, name, err))
			}
			l.filters = append(l.filters, filter)
		}
	}
	return nil
}

func (l *Loader) detachFilters() error {
	retained, err := detachOwned(l.filters, netlink.FilterDel)
	l.filters = retained
	return err
}

func detachOwned(filters []netlink.Filter, remove func(netlink.Filter) error) ([]netlink.Filter, error) {
	var errs []error
	failed := make(map[int]bool)
	for i := len(filters) - 1; i >= 0; i-- {
		if err := remove(filters[i]); err != nil {
			errs = append(errs, err)
			failed[i] = true
		}
	}
	retained := make([]netlink.Filter, 0, len(failed))
	for i, filter := range filters {
		if failed[i] {
			retained = append(retained, filter)
		}
	}
	return retained, errors.Join(errs...)
}
func (l *Loader) attachFailure(root error) error { return errors.Join(root, l.detachFilters()) }

func allowedLink(device netlink.Link) bool {
	if device.Attrs().Flags&net.FlagLoopback != 0 {
		return false
	}
	switch device.Type() {
	case "device", "bond", "vlan":
		return true
	default:
		return false
	}
}
func (l *Loader) Close() error {
	var errs []error
	errs = append(errs, l.detachFilters())
	if l.trace != nil {
		if err := l.trace.Close(); err != nil {
			errs = append(errs, err)
		} else {
			l.trace = nil
		}
	}
	if l.collection != nil {
		l.collection.Close()
		l.collection = nil
	}
	return errors.Join(errs...)
}

func (l *Loader) Snapshot() ([]flow.Record, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return nil, fmt.Errorf("read monotonic clock: %w", err)
	}
	now, mono := time.Now(), time.Duration(ts.Nano())
	records := make([]flow.Record, 0)
	it := l.flows.Iterate()
	var key FlowKey
	var value FlowValue
	for it.Next(&key, &value) {
		record, err := DecodeRecord(key, value, now, mono)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate flows map: %w", err)
	}
	return records, nil
}
