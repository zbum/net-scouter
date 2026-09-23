//go:build linux

package ebpf

import (
	"errors"
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
