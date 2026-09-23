//go:build linux

package agent

import (
	"path/filepath"
	"testing"
)

func TestInstanceLockRejectsConcurrentOwner(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "agent.lock")
	first, err := AcquireInstanceLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := AcquireInstanceLock(path); err == nil {
		t.Fatal("second lock succeeded")
	}
}
