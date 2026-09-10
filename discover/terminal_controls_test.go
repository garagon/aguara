package discover

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestFormatTreeEscapesParsedControls(t *testing.T) {
	var raw map[string]json.RawMessage
	err := json.Unmarshal([]byte(`{"mcpServers":{"server\u001b[2J":{"command":"node\rspoof","args":["arg\u001b]0;spoof\u0007"]}}}`), &raw)
	if err != nil {
		t.Fatal(err)
	}
	result := &Result{Clients: []ClientResult{{Client: "cursor", Path: "caf\u00e9/config\nspoof.json", Servers: extractServersFromKey(raw, "mcpServers")}}}
	if len(result.Clients[0].Servers) != 1 {
		t.Fatal("fixture did not parse")
	}
	before, _ := json.Marshal(result)
	out := FormatTree(result)
	for _, control := range []string{"\x1b", "\r", "\x07", "\nspoof"} {
		if strings.Contains(out, control) {
			t.Fatalf("control survived: %q", control)
		}
	}
	for _, want := range []string{`server\x1b[2J`, `node\rspoof`, `arg\x1b]0;spoof\a`, "caf\u00e9", "Cursor"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	after, _ := json.Marshal(result)
	if !bytes.Equal(before, after) {
		t.Error("source JSON changed")
	}
}
