//go:build !linux

package ebpf

import (
	"fmt"

	"github.com/example/net-scouter/internal/flow"
)

type Loader struct{}

func Open(string, uint32) (*Loader, error) {
	return nil, fmt.Errorf("eBPF collection loading requires Linux")
}
func (l *Loader) AttachTracepoint() (bool, error) {
	return false, fmt.Errorf("tracepoint attachment requires Linux")
}
func (l *Loader) ConnectionCounting() (bool, string) { return false, "" }
func (l *Loader) SetCapture(bool, bool, bool, bool) error {
	return fmt.Errorf("capture configuration requires Linux")
}
func (l *Loader) AttachTC([]string, bool) error { return fmt.Errorf("TC attachment requires Linux") }
func (l *Loader) Close() error                  { return nil }
func (l *Loader) Snapshot() ([]flow.Record, error) {
	return nil, fmt.Errorf("flow snapshots require Linux")
}
