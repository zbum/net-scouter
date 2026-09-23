//go:build !linux

package platform

import "runtime"

func collectProbes() []Probe {
	return []Probe{{
		Name:     "OS",
		Status:   "MISSING",
		Detail:   runtime.GOOS + " is not a supported agent OS",
		Required: true,
	}}
}
