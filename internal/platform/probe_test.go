package platform

import (
	"strings"
	"testing"
)

func TestOptionState(t *testing.T) {
	t.Parallel()
	config := strings.Join([]string{
		"CONFIG_BPF_SYSCALL=y",
		"CONFIG_NET_CLS_BPF=m",
		"# CONFIG_BPF_EVENTS is not set",
		"CONFIG_OTHER=n",
	}, "\n")
	if optionState(config, "CONFIG_BPF_SYSCALL") != "y" || optionState(config, "CONFIG_NET_CLS_BPF") != "m" {
		t.Fatalf("enabled options parsed wrong")
	}
	if optionState(config, "CONFIG_BPF_EVENTS") != "n" || optionState(config, "CONFIG_MISSING") != "absent" {
		t.Fatalf("disabled or absent options parsed wrong")
	}
}

func TestBPFFSMounted(t *testing.T) {
	t.Parallel()
	mounts := "sysfs /sys sysfs rw 0 0\nbpf /sys/fs/bpf bpf rw,mode=700 0 0\n"
	if !bpffsMounted(mounts) {
		t.Fatal("mounted bpffs not detected")
	}
	if bpffsMounted("proc /proc proc rw 0 0\n") {
		t.Fatal("unrelated mounts detected as bpffs")
	}
}

func TestKernelConfigProbe(t *testing.T) {
	t.Parallel()
	enabled := "CONFIG_BPF_SYSCALL=y\nCONFIG_NET_CLS_BPF=y\nCONFIG_BPF_EVENTS=y\n"
	if probe := kernelConfigProbe(enabled, true); probe.Status != "OK" || probe.Required {
		t.Fatalf("enabled config: %+v", probe)
	}
	disabled := "# CONFIG_BPF_SYSCALL is not set\nCONFIG_NET_CLS_BPF=y\n"
	probe := kernelConfigProbe(disabled, true)
	if probe.Status != "MISSING" || !probe.Required || !strings.Contains(probe.Detail, "CONFIG_BPF_SYSCALL") {
		t.Fatalf("disabled config: %+v", probe)
	}
	if probe := kernelConfigProbe("", false); probe.Status != "WARN" || probe.Required {
		t.Fatalf("missing config file: %+v", probe)
	}
}

func TestSummarizeRequiredProbe(t *testing.T) {
	t.Parallel()
	if err := summarize([]Probe{{Name: "BPF syscall", Status: "OK"}}); err != nil {
		t.Fatal(err)
	}
	err := summarize([]Probe{{Name: "OS", Status: "MISSING", Required: true}})
	if err == nil || !strings.Contains(err.Error(), "OS") {
		t.Fatalf("err=%v", err)
	}
}
