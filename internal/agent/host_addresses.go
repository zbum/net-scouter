package agent

import (
	"fmt"
	"net"
	"net/netip"
)

// ResolveHostAddresses returns the addresses assigned to the selected uplinks.
// Every selected interface must have an address in an enabled IP family.
func ResolveHostAddresses(names []string, ipv4, ipv6 bool) ([]netip.Addr, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("no interfaces selected for host address scope")
	}
	return resolveHostAddresses(names, ipv4, ipv6, func(name string) ([]net.Addr, error) {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return nil, err
		}
		return iface.Addrs()
	})
}

func resolveHostAddresses(names []string, ipv4, ipv6 bool, lookup func(string) ([]net.Addr, error)) ([]netip.Addr, error) {
	seen := make(map[netip.Addr]struct{})
	var result []netip.Addr
	for _, name := range names {
		addrs, err := lookup(name)
		if err != nil {
			return nil, fmt.Errorf("resolve interface %s addresses: %w", name, err)
		}
		found := false
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || (ip.Is4() && !ipv4) || (ip.Is6() && !ipv6) {
				continue
			}
			found = true
			if _, duplicate := seen[ip]; !duplicate {
				seen[ip] = struct{}{}
				result = append(result, ip)
			}
		}
		if !found {
			return nil, fmt.Errorf("interface %s has no address in an enabled IP family", name)
		}
	}
	return result, nil
}
