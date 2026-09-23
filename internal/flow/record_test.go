package flow

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRecordJSONIncludesTCPConnections(t *testing.T) {
	t.Parallel()

	encoded, err := json.Marshal(Record{Protocol: 6, Connections: 3})
	if err != nil {
		t.Fatalf("marshal Record: %v", err)
	}
	if !strings.Contains(string(encoded), `"connections":3`) {
		t.Fatalf("Record JSON = %s, want TCP connection count", encoded)
	}
}

func TestRecordJSONOmitsZeroConnections(t *testing.T) {
	t.Parallel()

	encoded, err := json.Marshal(Record{Protocol: 17})
	if err != nil {
		t.Fatalf("marshal Record: %v", err)
	}
	if strings.Contains(string(encoded), `"connections"`) {
		t.Fatalf("Record JSON = %s, want no UDP connection count", encoded)
	}
}
