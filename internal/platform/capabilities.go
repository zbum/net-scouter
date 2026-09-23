package platform

import (
	"fmt"
	"io"
	"os"
	"runtime"
)

func PrintCheck(w io.Writer) error {
	fmt.Fprintln(w, "Net Scouter Environment Check")
	fmt.Fprintf(w, "GOOS/GOARCH          %s/%s\n", runtime.GOOS, runtime.GOARCH)

	if runtime.GOOS != "linux" {
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		fmt.Fprintln(w, "BTF                  OK")
	} else {
		fmt.Fprintln(w, "BTF                  NOT FOUND")
	}

	fmt.Fprintln(w, "eBPF feature probing TODO: implement native capability checks")
	return nil
}
