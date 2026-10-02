package agent

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// DockerNetworks discovers subnets on Docker's conventional local bridges.
func DockerNetworks() ([]netip.Prefix, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	return dockerNetworks(interfaces, func(i net.Interface) ([]net.Addr, error) { return i.Addrs() })
}

func dockerNetworks(interfaces []net.Interface, addresses func(net.Interface) ([]net.Addr, error)) ([]netip.Prefix, error) {
	var result []netip.Prefix
	for _, iface := range interfaces {
		id, bridge := strings.CutPrefix(iface.Name, "br-")
		_, hexErr := hex.DecodeString(id)
		if iface.Name != "docker0" && !(bridge && len(id) == 12 && hexErr == nil) {
			continue
		}
		addrs, err := addresses(iface)
		if err != nil {
			return nil, fmt.Errorf("Docker bridge %s: %w", iface.Name, err)
		}
		for _, addr := range addrs {
			prefix, err := netip.ParsePrefix(addr.String())
			if err != nil || prefix.Bits() == 0 || prefix.Addr().IsLinkLocalUnicast() || prefix.Addr().IsMulticast() {
				continue
			}
			result = append(result, prefix.Masked())
		}
	}
	slices.SortFunc(result, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
	return slices.Compact(result), nil
}

// EnableDockerExclusions enables periodic discovery before flow aggregation.
func (a *Agent) EnableDockerExclusions() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.dockerLookup = DockerNetworks
	a.refreshDockerNetworks()
	if a.dockerError != "" {
		return fmt.Errorf("discover Docker networks: %s", a.dockerError)
	}
	return nil
}

func (a *Agent) refreshDockerNetworks() {
	if a.dockerLookup == nil || time.Since(a.dockerChecked) < 30*time.Second {
		return
	}
	a.dockerChecked = time.Now()
	prefixes, err := a.dockerLookup()
	if err != nil {
		a.dockerError = err.Error()
		return // Retain the last known exclusions on a transient discovery failure.
	}
	a.dockerError = ""
	a.dockerNetworks = prefixes
	for key, record := range a.stored {
		if a.excluded(record) {
			delete(a.stored, key)
			delete(a.dirtyKeys, key)
			if _, exists := a.persistedKeys[key]; exists {
				a.pendingDeletes[key] = struct{}{}
			}
		}
	}
}
