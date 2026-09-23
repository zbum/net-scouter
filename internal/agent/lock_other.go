//go:build !linux

package agent

import "fmt"

type InstanceLock struct{}

func AcquireInstanceLock(string) (*InstanceLock, error) {
	return nil, fmt.Errorf("instance locking requires Linux")
}
func (l *InstanceLock) Close() error { return nil }
