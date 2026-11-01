package aguara_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/garagon/aguara"
	"github.com/stretchr/testify/require"
)

const kubeIdentityRule = "K8S_IDENTITY_CAPABILITIES_001"

func kubePod(add, extra string) string {
	return `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"example"},"spec":{"containers":[{"name":"app","image":"example/app","securityContext":{"capabilities":` + add + `}` + extra + `}]}}`
}

func kubeFindings(result *aguara.ScanResult, id string) []aguara.Finding {
	var out []aguara.Finding
	for _, f := range result.Findings {
		if f.RuleID == id {
			out = append(out, f)
		}
	}
	return out
}

func TestKubePolicyOwnership(t *testing.T) {
	sc, err := aguara.NewScanner(aguara.WithWorkers(1), aguara.WithDeduplicateMode(aguara.DeduplicateSameRuleOnly))
	require.NoError(t, err)
	base := kubePod(`{"add":["SETUID","SETGID"]}`, "")
	cases := []struct{ name, path, content string }{
		{"identity pair", "pod.json", base},
		{"uid", "pod.json", kubePod(`{"add":["SETUID"]}`, "")},
		{"gid", "pod.json", kubePod(`{"add":["SETGID"]}`, "")},
		{"drop all", "pod.json", kubePod(`{"drop":["ALL"],"add":["SETUID"]}`, "")},
		{"add before drop", "pod.json", kubePod(`{"add":["SETUID"],"drop":["ALL"]}`, "")},
		{"drop same", "pod.json", kubePod(`{"add":["SETUID"],"drop":["SETUID"]}`, "")},
		{"duplicates in list", "pod.json", kubePod(`{"add":["SETUID","SETUID"]}`, "")},
		{"init", "pod.json", strings.Replace(base, `"containers"`, `"initContainers"`, 1)},
		{"ephemeral", "pod.json", strings.Replace(base, `"containers"`, `"ephemeralContainers"`, 1)},
		{"escaped JSON", "pod.json", strings.ReplaceAll(strings.Replace(base, `"capabilities"`, `"capabil\u0069ties"`, 1), "SETUID", `\u0053ETUID`)},
		{"flow yaml", "arbitrary.yml", `apiVersion: v1
kind: Pod
metadata: {name: sample}
spec:
  containers:
  - name: app
    securityContext:
      capabilities: {add: [SETUID, SETGID]}
`},
		{"list", "list.json", `{"apiVersion":"v1","kind":"List","items":[` + base + `]}`},
		{"multi doc", "pods.yaml", "---\n" + base + "\n---\nkind: ConfigMap\napiVersion: v1\n"},
		{"linux", "pod.json", strings.Replace(base, `"spec":{`, `"spec":{"os":{"name":"linux"},`, 1)},
		{"nonroot", "pod.json", strings.Replace(base, `"securityContext":{`, `"securityContext":{"runAsNonRoot":true,"runAsUser":1000,"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,`, 1)},
	}
	for _, controller := range []struct{ api, kind, path string }{
		{"v1", "ReplicationController", "template"},
		{"apps/v1", "Deployment", "template"}, {"apps/v1", "DaemonSet", "template"},
		{"apps/v1", "StatefulSet", "template"}, {"apps/v1", "ReplicaSet", "template"},
		{"batch/v1", "Job", "template"}, {"batch/v1", "CronJob", "cron"},
	} {
		var pod map[string]any
		require.NoError(t, json.Unmarshal([]byte(base), &pod))
		spec := map[string]any{"template": map[string]any{"spec": pod["spec"]}}
		if controller.path == "cron" {
			spec = map[string]any{"jobTemplate": map[string]any{"spec": spec}}
		}
		b, err := json.Marshal(map[string]any{"apiVersion": controller.api, "kind": controller.kind, "spec": spec})
		require.NoError(t, err)
		cases = append(cases, struct{ name, path, content string }{controller.kind, "controller.json", string(b)})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := sc.ScanContent(context.Background(), tc.content, tc.path)
			require.NoError(t, err)
			fs := kubeFindings(result, kubeIdentityRule)
			require.Len(t, fs, 1)
			require.Equal(t, aguara.SeverityLow, fs[0].Severity)
			require.Equal(t, "context", fs[0].DecisionImpact)
			require.Equal(t, "container-security", fs[0].Category)
			require.Equal(t, "kube-policy", fs[0].Analyzer)
			require.Empty(t, kubeFindings(result, "SUPPLY_007"))
		})
	}
}

func TestKubePolicyFallbackAndNegatives(t *testing.T) {
	sc, err := aguara.NewScanner(aguara.WithWorkers(1), aguara.WithDeduplicateMode(aguara.DeduplicateSameRuleOnly))
	require.NoError(t, err)
	base := kubePod(`{"add":["SETUID"]}`, "")
	cases := []struct {
		name, path, content string
		legacy              bool
	}{
		{"fragment", "pod.yaml", "capabilities: {add: [SETUID]}", true},
		{"wrong group", "pod.json", strings.Replace(base, `"v1"`, `"fake/v1"`, 1), true},
		{"custom kind", "pod.json", strings.Replace(base, `"Pod"`, `"CustomPod"`, 1), true},
		{"windows", "pod.json", strings.Replace(base, `"spec":{`, `"spec":{"os":{"name":"windows"},`, 1), true},
		{"unknown OS", "pod.json", strings.Replace(base, `"spec":{`, `"spec":{"os":{"name":"other"},`, 1), true},
		{"wrong path", "pod.json", strings.Replace(base, `"securityContext"`, `"other"`, 1), true},
		{"case", "pod.json", strings.Replace(base, `"Pod"`, `"pod"`, 1), true},
		{"lower value", "pod.json", strings.Replace(base, "SETUID", "setuid", 1), true},
		{"CAP prefix", "pod.json", strings.Replace(base, "SETUID", "CAP_SETUID", 1), true},
		{"executable value", "pod.json", strings.Replace(base, "SETUID", "os.setuid(0)", 1), true},
		{"wrong list", "pod.json", strings.Replace(base, `["SETUID"]`, `"SETUID"`, 1), true},
		{"mixed list", "pod.json", strings.Replace(base, `["SETUID"]`, `["SETUID",true]`, 1), true},
		{"duplicate key", "pod.json", strings.Replace(base, `"kind":"Pod"`, `"kind":"Pod","kind":"Pod"`, 1), true},
		{"malformed suffix", "pods.yaml", base + "\n---\nx: [", true},
		{"anchor", "pods.yaml", "defaults: &caps [SETUID]\n---\n" + base, true},
		{"merge", "pods.yaml", "defaults: &base {}\nconfig: {<<: *base}\n---\n" + base, true},
		{"tag", "pods.yaml", "tag: !!str x\n---\n" + base, true},
		{"multiline scalar", "pods.yaml", "description: |\n  benign\n---\n" + base, true},
		{"BOM", "pod.yaml", "\ufeff" + base, true},
		{"normalized source", "pod.json", strings.Replace(base, "example", "\uff21", 1), true},
		{"ConfigMap data", "config.json", `{"apiVersion":"v1","kind":"ConfigMap","data":{"example":` + base + `}}`, true},
		{"wrong nesting", "pod.json", `{"apiVersion":"v1","kind":"Pod","data":` + base + `}`, true},
		{"list nesting", "list.json", `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"v1","kind":"List","items":[` + base + `]}]}`, true},
		{"markdown", "README.md", "```json\n" + base + "\n```", true},
		{"drop only", "pod.json", kubePod(`{"drop":["SETUID","SETGID"]}`, ""), false},
		{"drop ALL", "pod.json", kubePod(`{"drop":["ALL"]}`, ""), false},
		{"empty", "pod.json", kubePod(`{"add":[]}`, ""), false},
		{"null", "pod.json", kubePod(`{"add":null}`, ""), false},
		{"safe addition", "pod.json", kubePod(`{"add":["NET_BIND_SERVICE"]}`, ""), false},
		{"absent", "pod.json", kubePod(`{}`, ""), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := sc.ScanContent(context.Background(), tc.content, tc.path)
			require.NoError(t, err)
			require.Empty(t, kubeFindings(result, kubeIdentityRule))
			require.Equal(t, tc.legacy, len(kubeFindings(result, "SUPPLY_007")) > 0)
		})
	}
}

func TestKubePolicyRetainsCommands(t *testing.T) {
	sc, err := aguara.NewScanner(aguara.WithWorkers(1), aguara.WithDeduplicateMode(aguara.DeduplicateSameRuleOnly))
	require.NoError(t, err)
	for _, command := range []string{"process.setuid(0)", "os.setgid(0)", "sudo bash -c id", "sudo chmod +s /tmp/helper", "chown root:root /tmp/helper", "setcap cap_setuid+ep /tmp/bin"} {
		t.Run(command, func(t *testing.T) {
			quoted, err := json.Marshal(command)
			require.NoError(t, err)
			content := kubePod(`{"add":["SETUID"]}`, `,"command":[`+string(quoted)+`]`)
			result, err := sc.ScanContent(context.Background(), content, "pod.json")
			require.NoError(t, err)
			require.Len(t, kubeFindings(result, kubeIdentityRule), 1)
			fs := kubeFindings(result, "SUPPLY_007")
			require.Len(t, fs, 1)
			require.Equal(t, aguara.SeverityHigh, fs[0].Severity)
			require.Equal(t, "review", fs[0].DecisionImpact)
		})
	}
	// Use a payload beyond the existing decoder's minimum blob length; a
	// short base64 string would only test the unrelated raw SETUID match.
	payload := []byte("sudo chmod +s /usr/local/bin/exploit")
	for _, encoded := range []string{base64.StdEncoding.EncodeToString(payload), hex.EncodeToString(payload)} {
		content := kubePod(`{"add":["SETUID"]}`, `,"payload":"`+encoded+`"`)
		result, err := sc.ScanContent(context.Background(), content, "pod.json")
		require.NoError(t, err)
		require.NotEmpty(t, kubeFindings(result, "SUPPLY_007"))
	}
	content := kubePod(`{"add":["ALL","SETUID"]}`, "")
	result, err := sc.ScanContent(context.Background(), content, "pod.json")
	require.NoError(t, err)
	require.Len(t, kubeFindings(result, "MCP_009"), 1)
	require.Len(t, kubeFindings(result, kubeIdentityRule), 1)
}

func TestKubePolicyPublicContract(t *testing.T) {
	content := kubePod(`{"add":["SETUID"]}`, "")
	for _, disabled := range []string{"", kubeIdentityRule, "SUPPLY_007"} {
		t.Run("disabled="+disabled, func(t *testing.T) {
			sc, err := aguara.NewScanner(aguara.WithWorkers(1), aguara.WithDisabledRules(disabled))
			require.NoError(t, err)
			result, err := sc.ScanContent(context.Background(), content, "pod.json")
			require.NoError(t, err)
			require.Empty(t, kubeFindings(result, "SUPPLY_007"))
			want := 1
			if disabled == kubeIdentityRule {
				want = 0
			}
			require.Len(t, kubeFindings(result, kubeIdentityRule), want)
		})
	}
	detail, err := aguara.ExplainRule(kubeIdentityRule)
	require.NoError(t, err)
	require.Equal(t, "LOW", detail.Severity)
	require.Equal(t, "context", detail.DecisionImpact)
	require.Equal(t, "container-security", detail.Category)
	require.Equal(t, "kube-policy", detail.Analyzer)

	// Analyzer rules other than the MCP_009 compatibility exception do not
	// support RuleOverride; their catalog must not pretend otherwise.
	sc, err := aguara.NewScanner(aguara.WithWorkers(1), aguara.WithRuleOverrides(map[string]aguara.RuleOverride{
		kubeIdentityRule: {Disabled: true, Severity: "HIGH"},
	}))
	require.NoError(t, err)
	result, err := sc.ScanContent(context.Background(), content, "pod.json")
	require.NoError(t, err)
	fs := kubeFindings(result, kubeIdentityRule)
	require.Len(t, fs, 1)
	require.Equal(t, aguara.SeverityLow, fs[0].Severity)
	detail, err = sc.ExplainRule(kubeIdentityRule)
	require.NoError(t, err)
	require.Equal(t, "LOW", detail.Severity)

	path := filepath.Join(t.TempDir(), "pod.json")
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	disk, err := aguara.Scan(context.Background(), path, aguara.WithWorkers(1))
	require.NoError(t, err)
	inline, err := aguara.ScanContent(context.Background(), content, "pod.json", aguara.WithWorkers(1))
	require.NoError(t, err)
	require.Len(t, kubeFindings(disk, kubeIdentityRule), 1)
	require.Len(t, kubeFindings(inline, kubeIdentityRule), 1)
	for _, f := range kubeFindings(inline, kubeIdentityRule) {
		require.Equal(t, "context", f.DecisionImpact)
		require.Equal(t, 1, f.Line)
		require.Equal(t, "SETUID", strings.Trim(string([]byte(content)[f.Column-1:f.Column+7]), `"`), fmt.Sprint(f))
	}
}

func TestKubePolicyDedupAndIsolation(t *testing.T) {
	for _, mode := range []aguara.DeduplicateMode{aguara.DeduplicateFull, aguara.DeduplicateSameRuleOnly} {
		sc, err := aguara.NewScanner(aguara.WithWorkers(1), aguara.WithDeduplicateMode(mode))
		require.NoError(t, err)
		content := kubePod(`{"add":["SETUID"]}`, `,"command":["process.setuid(0)"]`)
		result, err := sc.ScanContent(context.Background(), content, "pod.json")
		require.NoError(t, err)
		require.Len(t, kubeFindings(result, "SUPPLY_007"), 1)
		if mode == aguara.DeduplicateFull {
			require.Empty(t, kubeFindings(result, kubeIdentityRule))
		} else {
			require.Len(t, kubeFindings(result, kubeIdentityRule), 1)
		}
		// One-line declarations obey the existing same-rule dedup contract.
		content = `{"apiVersion":"v1","kind":"List","items":[` + kubePod(`{"add":["SETUID"]}`, "") + "," + kubePod(`{"add":["SETGID"]}`, "") + `]}`
		result, err = sc.ScanContent(context.Background(), content, "pods.json")
		require.NoError(t, err)
		require.Len(t, kubeFindings(result, kubeIdentityRule), 1)
		require.Empty(t, kubeFindings(result, "SUPPLY_007"))
	}
	sc, err := aguara.NewScanner(aguara.WithWorkers(1), aguara.WithDeduplicateMode(aguara.DeduplicateSameRuleOnly))
	require.NoError(t, err)
	content := kubePod(`{"add":["SETUID"]}`, "") + "\n---\ncommand: |\n  process.setuid(0)\n"
	result, err := sc.ScanContent(context.Background(), content, "pods.yaml")
	require.NoError(t, err)
	// Unsupported scalar extents forbid a partial ownership transfer.
	require.Empty(t, kubeFindings(result, kubeIdentityRule))
	require.Len(t, kubeFindings(result, "SUPPLY_007"), 2)
	content = kubePod(`{"add":["SETUID"]}`, "") + "\n---\ncommand: 'process.setuid(0)'\n"
	result, err = sc.ScanContent(context.Background(), content, "pods.yaml")
	require.NoError(t, err)
	require.Len(t, kubeFindings(result, kubeIdentityRule), 1)
	require.Len(t, kubeFindings(result, "SUPPLY_007"), 1)
	require.Equal(t, 3, kubeFindings(result, "SUPPLY_007")[0].Line)
}
