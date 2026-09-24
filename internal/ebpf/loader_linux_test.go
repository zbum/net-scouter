//go:build linux

package ebpf

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestDetachOwnedRetainsOnlyFailedFilters(t *testing.T) {
	t.Parallel()
	first := &netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{Handle: 1}}
	second := &netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{Handle: 2}}
	third := &netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{Handle: 3}}
	retained, err := detachOwned([]netlink.Filter{first, second, third}, func(filter netlink.Filter) error {
		if filter.Attrs().Handle != 1 {
			return errors.New("busy")
		}
		return nil
	})
	if err == nil || len(retained) != 2 || retained[0].Attrs().Handle != 2 || retained[1].Attrs().Handle != 3 {
		t.Fatalf("retained=%v err=%v", retained, err)
	}
}

func TestMakeHostAddressKeyNormalizesIPv4AndIPv6(t *testing.T) {
	t.Parallel()
	v4, err := makeHostAddressKey(netip.MustParseAddr("::ffff:192.0.2.10"))
	if err != nil || v4.Family != 2 || v4.Addr != [16]byte{192, 0, 2, 10} {
		t.Fatalf("IPv4-mapped key = %+v, %v", v4, err)
	}
	v6, err := makeHostAddressKey(netip.MustParseAddr("2001:db8::10"))
	if err != nil || v6.Family != 10 || v6.Addr != netip.MustParseAddr("2001:db8::10").As16() {
		t.Fatalf("IPv6 key = %+v, %v", v6, err)
	}
	if _, err := makeHostAddressKey(netip.Addr{}); err == nil {
		t.Fatal("invalid address accepted")
	}
}

func TestAllowedLinkPolicy(t *testing.T) {
	t.Parallel()
	if !allowedLink(&netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}}) {
		t.Fatal("physical device rejected")
	}
	if allowedLink(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "dummy0"}}) {
		t.Fatal("dummy accepted")
	}
}

func TestAttachTracepointRejectsRepeatedAttempt(t *testing.T) {
	t.Parallel()
	l := &Loader{traceAttempted: true}
	if _, err := l.AttachTracepoint(); err == nil {
		t.Fatal("repeated attempt succeeded")
	}
}
