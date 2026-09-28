//go:build linux

package platform

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/zbum/net-scouter/internal/ebpf"
)

func collectProbes() []Probe {
	probes := []Probe{
		bpfProbe(),
		{Name: "kernel", Status: "OK", Detail: kernelRelease()},
		bpffsProbe(),
		btfProbe(),
		tracepointProbe(),
		euidProbe(),
	}
	config, found := loadKernelConfig()
	probes = append(probes, kernelConfigProbe(config, found))
	return probes
}

func bpfProbe() Probe {
	var attr struct {
		StartID   uint32
		NextID    uint32
		OpenFlags uint32
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(unix.BPF_PROG_GET_NEXT_ID), uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	switch errno {
	case 0, unix.ENOENT:
		return Probe{Name: "BPF syscall", Status: "OK", Detail: "available"}
	case unix.EPERM, unix.EACCES:
		return Probe{Name: "BPF syscall", Status: "OK", Detail: "available (enumerating programs requires permission)"}
	case unix.ENOSYS:
		return Probe{Name: "BPF syscall", Status: "MISSING", Detail: "syscall not implemented", Required: true}
	default:
		return Probe{Name: "BPF syscall", Status: "OK", Detail: "available (" + errno.Error() + ")"}
	}
}

func kernelRelease() string {
	var name unix.Utsname
	if err := unix.Uname(&name); err != nil {
		return "unknown"
	}
	return unix.ByteSliceToString(name.Release[:])
}

func bpffsProbe() Probe {
	body, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return Probe{Name: "bpffs", Status: "WARN", Detail: "mount table unreadable"}
	}
	if bpffsMounted(string(body)) {
		return Probe{Name: "bpffs", Status: "OK", Detail: "mounted"}
	}
	return Probe{Name: "bpffs", Status: "WARN", Detail: "not mounted; verifier pinning needs /sys/fs/bpf"}
}

func btfProbe() Probe {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		return Probe{Name: "BTF", Status: "OK", Detail: "present"}
	}
	return Probe{Name: "BTF", Status: "WARN", Detail: "vmlinux BTF not found"}
}

func tracepointProbe() Probe {
	for _, path := range ebpf.TraceFormatCandidates() {
		if _, err := os.Stat(path); err == nil {
			return Probe{Name: "TCP state tracepoint", Status: "OK", Detail: path}
		}
	}
	return Probe{Name: "TCP state tracepoint", Status: "WARN", Detail: "format file not found; connection counting will be disabled"}
}

func euidProbe() Probe {
	euid := unix.Geteuid()
	if euid == 0 {
		return Probe{Name: "euid", Status: "OK", Detail: "root"}
	}
	return Probe{Name: "euid", Status: "WARN", Detail: "uid " + strconv.Itoa(euid) + "; TC/BPF attach needs root or equivalent capabilities"}
}

func loadKernelConfig() (string, bool) {
	if text, ok := readGzipFile("/proc/config.gz"); ok {
		return text, true
	}
	release := kernelRelease()
	if release == "" || release == "unknown" {
		return "", false
	}
	body, err := os.ReadFile("/boot/config-" + release)
	if err != nil {
		return "", false
	}
	return string(body), true
}

func readGzipFile(path string) (string, bool) {
	body, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return "", false
	}
	defer reader.Close()
	text, err := io.ReadAll(reader)
	if err != nil {
		return "", false
	}
	return string(text), true
}
