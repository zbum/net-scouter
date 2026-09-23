package ebpf

import (
	"fmt"
	"io"
	"io/fs"
	"strings"
	"testing"
)

func TestParseTraceFormat(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, text string
		want       TraceABI
	}{
		{"4.18", fixture(1, 31, 35, 39, 55), TraceProtocolU8},
		{"5.15", fixture(2, 32, 36, 40, 56), TraceProtocolU16},
		{"partial", "field:int oldstate; offset:16; size:4;", TraceUnknown},
		{"malformed", fixture(2, 33, 37, 41, 57), TraceUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseTraceFormat(strings.NewReader(tc.text))
			if err != nil || got != tc.want {
				t.Fatalf("got %v, %v", got, err)
			}
		})
	}
}

func TestProbeTraceFormatFallbackOnlyForMissingPath(t *testing.T) {
	t.Parallel()
	valid := fixture(2, 32, 36, 40, 56)
	abi, err := probeTraceFormat([]string{"primary", "fallback"}, func(path string) (io.ReadCloser, error) {
		if path == "primary" {
			return nil, fs.ErrNotExist
		}
		return io.NopCloser(strings.NewReader(valid)), nil
	})
	if err != nil || abi != TraceProtocolU16 {
		t.Fatalf("fallback: %v %v", abi, err)
	}
	_, err = probeTraceFormat([]string{"primary", "fallback"}, func(string) (io.ReadCloser, error) { return nil, fs.ErrPermission })
	if err == nil {
		t.Fatal("permission error was degraded")
	}
}

func fixture(protocolSize, saddr, daddr, saddr6, daddr6 int) string {
	return fmt.Sprintf("field:int oldstate; offset:16; size:4;\nfield:int newstate; offset:20; size:4;\nfield:__u16 sport; offset:24; size:2;\nfield:__u16 dport; offset:26; size:2;\nfield:__u16 family; offset:28; size:2;\nfield:__u16 protocol; offset:30; size:%d;\nfield:__u8 saddr[4]; offset:%d; size:4;\nfield:__u8 daddr[4]; offset:%d; size:4;\nfield:__u8 saddr_v6[16]; offset:%d; size:16;\nfield:__u8 daddr_v6[16]; offset:%d; size:16;", protocolSize, saddr, daddr, saddr6, daddr6)
}
