package ebpf

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
)

var traceFormatPaths = []string{"/sys/kernel/tracing/events/sock/inet_sock_set_state/format", "/sys/kernel/debug/tracing/events/sock/inet_sock_set_state/format"}

func probeTraceFormat(paths []string, open func(string) (io.ReadCloser, error)) (TraceABI, error) {
	for _, path := range paths {
		reader, err := open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return TraceUnknown, fmt.Errorf("open trace format %s: %w", path, err)
		}
		abi, parseErr := ParseTraceFormat(reader)
		closeErr := reader.Close()
		if parseErr != nil {
			return TraceUnknown, parseErr
		}
		if closeErr != nil {
			return TraceUnknown, closeErr
		}
		return abi, nil
	}
	return TraceUnknown, nil
}

type TraceABI uint8

const (
	TraceUnknown TraceABI = iota
	TraceProtocolU8
	TraceProtocolU16
)

var traceField = regexp.MustCompile(`field:.*\b(oldstate|newstate|sport|dport|family|protocol|saddr|daddr|saddr_v6|daddr_v6)\b.*offset:(\d+);.*size:(\d+);`)

var commonTraceFields = map[string][2]int{"oldstate": {16, 4}, "newstate": {20, 4}, "sport": {24, 2}, "dport": {26, 2}, "family": {28, 2}}

func ParseTraceFormat(r io.Reader) (TraceABI, error) {
	fields := map[string][2]int{}
	s := bufio.NewScanner(r)
	for s.Scan() {
		m := traceField.FindStringSubmatch(s.Text())
		if len(m) == 4 {
			o, _ := strconv.Atoi(m[2])
			z, _ := strconv.Atoi(m[3])
			fields[m[1]] = [2]int{o, z}
		}
	}
	if err := s.Err(); err != nil {
		return TraceUnknown, fmt.Errorf("scan trace format: %w", err)
	}
	for name, want := range commonTraceFields {
		if fields[name] != want {
			return TraceUnknown, nil
		}
	}
	if fields["protocol"] == [2]int{30, 1} && fields["saddr"] == [2]int{31, 4} && fields["daddr"] == [2]int{35, 4} && fields["saddr_v6"] == [2]int{39, 16} && fields["daddr_v6"] == [2]int{55, 16} {
		return TraceProtocolU8, nil
	}
	if fields["protocol"] == [2]int{30, 2} && fields["saddr"] == [2]int{32, 4} && fields["daddr"] == [2]int{36, 4} && fields["saddr_v6"] == [2]int{40, 16} && fields["daddr_v6"] == [2]int{56, 16} {
		return TraceProtocolU16, nil
	}
	return TraceUnknown, nil
}
