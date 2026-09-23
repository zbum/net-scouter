package platform

import "strings"

func optionState(config, key string) string {
	if config == "" || key == "" {
		return "absent"
	}
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		switch line {
		case key + "=y":
			return "y"
		case key + "=m":
			return "m"
		case "# " + key + " is not set":
			return "n"
		}
	}
	return "absent"
}

func bpffsMounted(mounts string) bool {
	for _, line := range strings.Split(mounts, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[2] == "bpf" {
			return true
		}
	}
	return false
}

func kernelConfigProbe(config string, found bool) Probe {
	if !found {
		return Probe{Name: "kernel config", Status: "WARN", Detail: "not exposed"}
	}
	required := []string{"CONFIG_BPF_SYSCALL", "CONFIG_NET_CLS_BPF"}
	var disabled, absent []string
	for _, key := range required {
		switch optionState(config, key) {
		case "y", "m":
		case "n":
			disabled = append(disabled, key)
		default:
			absent = append(absent, key)
		}
	}
	if len(disabled) > 0 {
		return Probe{Name: "kernel config", Status: "MISSING", Detail: strings.Join(disabled, ", ") + " disabled", Required: true}
	}
	if optionState(config, "CONFIG_BPF_EVENTS") == "n" {
		return Probe{Name: "kernel config", Status: "WARN", Detail: "CONFIG_BPF_EVENTS disabled; connection counting will be unavailable"}
	}
	if len(absent) > 0 {
		return Probe{Name: "kernel config", Status: "WARN", Detail: "incomplete: " + strings.Join(absent, ", ")}
	}
	return Probe{Name: "kernel config", Status: "OK", Detail: "BPF syscall and TC classifier enabled"}
}
