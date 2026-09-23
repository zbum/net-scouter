package config

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Interfaces   []string    `yaml:"interfaces"`
	ObjectPath   string      `yaml:"objectPath"`
	AllowVirtual bool        `yaml:"allowVirtualInterfaces"`
	Aggregation  Aggregation `yaml:"aggregation"`
	Export       Export      `yaml:"export"`
	Exclude      Exclude     `yaml:"exclude"`
	Capture      Capture     `yaml:"capture"`
	Safety       Safety      `yaml:"safety"`
}

type Capture struct {
	IPv4 *bool `yaml:"ipv4"`
	IPv6 *bool `yaml:"ipv6"`
	TCP  *bool `yaml:"tcp"`
	UDP  *bool `yaml:"udp"`
	ICMP *bool `yaml:"icmp"`
}

type Safety struct {
	FailOpen *bool `yaml:"failOpen"`
}

type Aggregation struct {
	Interval time.Duration `yaml:"-"`
	MaxFlows uint32        `yaml:"maxFlows"`
}

func (a *Aggregation) UnmarshalYAML(node *yaml.Node) error {
	if err := rejectUnknown(node, "interval", "maxFlows"); err != nil {
		return err
	}
	var raw struct {
		Interval string `yaml:"interval"`
		MaxFlows uint32 `yaml:"maxFlows"`
	}
	if err := node.Decode(&raw); err != nil {
		return err
	}
	d, err := time.ParseDuration(raw.Interval)
	if err != nil {
		return fmt.Errorf("aggregation.interval: %w", err)
	}
	a.Interval, a.MaxFlows = d, raw.MaxFlows
	return nil
}

type Export struct {
	Type string `yaml:"type"`
	Path string `yaml:"path"`
}

type Exclude struct {
	Destinations  []string `yaml:"destinations"`
	WorkloadCIDRs []string `yaml:"workloadCIDRs"`
}

func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()
	var c Config
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return Config{}, fmt.Errorf("configuration must contain exactly one YAML document")
		}
		return Config{}, fmt.Errorf("decode trailing config: %w", err)
	}
	if c.ObjectPath == "" {
		c.ObjectPath = "/usr/lib/net-scouter/flow.bpf.o"
	}
	if c.Aggregation.Interval == 0 {
		c.Aggregation.Interval = 30 * time.Second
	}
	if c.Aggregation.MaxFlows == 0 {
		c.Aggregation.MaxFlows = 65536
	}
	if c.Aggregation.MaxFlows > 1_048_576 {
		return Config{}, fmt.Errorf("aggregation.maxFlows must not exceed 1048576")
	}
	if c.Export.Type == "" {
		c.Export.Type = "stdout"
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func (c Config) Validate() error {
	if len(c.Interfaces) == 0 {
		return fmt.Errorf("interfaces allowlist must not be empty")
	}
	seen := map[string]bool{}
	for _, name := range c.Interfaces {
		if name == "" || seen[name] {
			return fmt.Errorf("invalid or duplicate interface %q", name)
		}
		seen[name] = true
		if !c.AllowVirtual && isInternal(name) {
			return fmt.Errorf("interface %q is internal; set allowVirtualInterfaces explicitly to opt in", name)
		}
	}
	if c.Aggregation.Interval <= 0 {
		return fmt.Errorf("aggregation.interval must be positive")
	}
	if c.Aggregation.MaxFlows == 0 {
		return fmt.Errorf("aggregation.maxFlows must be positive")
	}
	if c.Export.Type != "stdout" || c.Export.Path != "" {
		return fmt.Errorf("export must use type stdout with no path")
	}
	if c.Capture.IPv4 == nil || c.Capture.IPv6 == nil || c.Capture.TCP == nil || c.Capture.UDP == nil || c.Capture.ICMP == nil {
		return fmt.Errorf("capture.ipv4, ipv6, tcp, udp, and icmp must be set")
	}
	if *c.Capture.ICMP {
		return fmt.Errorf("capture.icmp must be false")
	}
	if !*c.Capture.IPv4 && !*c.Capture.IPv6 {
		return fmt.Errorf("capture must enable ipv4 or ipv6")
	}
	if !*c.Capture.TCP && !*c.Capture.UDP {
		return fmt.Errorf("capture must enable tcp or udp")
	}
	if !enabled(c.Safety.FailOpen) {
		return fmt.Errorf("safety.failOpen must be true")
	}
	for _, value := range append(append([]string{}, c.Exclude.Destinations...), c.Exclude.WorkloadCIDRs...) {
		if _, err := netip.ParsePrefix(value); err != nil {
			return fmt.Errorf("invalid exclude CIDR %q: %w", value, err)
		}
	}
	return nil
}

func enabled(value *bool) bool { return value != nil && *value }

func isInternal(name string) bool {
	if name == "lo" || name == "docker0" {
		return true
	}
	for _, p := range []string{"cni", "veth", "cali", "flannel"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func rejectUnknown(node *yaml.Node, allowed ...string) error {
	known := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		known[key] = true
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if !known[node.Content[i].Value] {
			return fmt.Errorf("unknown field %q", node.Content[i].Value)
		}
	}
	return nil
}
