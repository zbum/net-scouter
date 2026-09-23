package platform

import (
	"fmt"
	"io"
	"runtime"
	"strings"
)

type Probe struct {
	Name     string
	Status   string
	Detail   string
	Required bool
}

func (p Probe) Line() string {
	if p.Detail == "" {
		return p.Status
	}
	return p.Status + " " + p.Detail
}

func PrintCheck(w io.Writer) error {
	fmt.Fprintln(w, "Net Scouter Environment Check")
	fmt.Fprintf(w, "%-22s %s/%s\n", "GOOS/GOARCH", runtime.GOOS, runtime.GOARCH)
	probes := collectProbes()
	for _, probe := range probes {
		fmt.Fprintf(w, "%-22s %s\n", probe.Name, probe.Line())
	}
	return summarize(probes)
}

func summarize(probes []Probe) error {
	var missing []string
	for _, probe := range probes {
		if probe.Required && probe.Status != "OK" {
			missing = append(missing, probe.Name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("missing required capabilities: %s", strings.Join(missing, ", "))
}
