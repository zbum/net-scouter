package query

import (
	"net"
	"net/netip"
)

func FilterLocal(result FlowsResult, includeLocal bool, local []netip.Addr) FlowsResult {
	if includeLocal {
		return result
	}
	filtered := make([]FlowView, 0, len(result.Records))
	for _, record := range result.Records {
		if sameAddress(record.SrcIP, record.DstIP) || (localEndpoint(record.SrcIP, local) && localEndpoint(record.DstIP, local)) {
			continue
		}
		filtered = append(filtered, record)
	}
	result.Records = filtered
	return result
}

func InterfaceAddrs(names []string) []netip.Addr {
	var out []netip.Addr
	for _, name := range names {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			parsed, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				continue
			}
			out = append(out, parsed.Unmap())
		}
	}
	return out
}

func sameAddress(left, right string) bool {
	src, srcErr := netip.ParseAddr(left)
	dst, dstErr := netip.ParseAddr(right)
	if srcErr != nil || dstErr != nil {
		return false
	}
	return src.Unmap() == dst.Unmap()
}

func localEndpoint(value string, local []netip.Addr) bool {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if addr.IsLoopback() {
		return true
	}
	for _, candidate := range local {
		if addr == candidate.Unmap() {
			return true
		}
	}
	return false
}
