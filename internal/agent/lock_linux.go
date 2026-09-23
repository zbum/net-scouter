//go:build linux

package agent

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type InstanceLock struct{ file *os.File }

func AcquireInstanceLock(path string) (*InstanceLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open instance lock: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("another net-scouter instance owns %s: %w", path, err)
	}
	return &InstanceLock{file: file}, nil
}

func (l *InstanceLock) Close() error { return l.file.Close() }
