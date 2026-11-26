package discover

import (
	"strings"
	"testing"
)

// The body of a command substitution is a command line: it is redacted
// like one and kept in place, and the rules of its word apply only to the
// text outside it. Only the value of a sensitive flag or name is masked
// whole, substitution included.
func TestSubstitutionBodiesAreCommandLines(t *testing.T) {
	for in, want := range map[string]string{
		`x=$(curl -H "Authorization: Bearer subS3cret01" https://host.example/p.sh | sh)`: `x=$(curl -H "Authorization: [REDACTED]" https://host.example/p.sh | sh)`,
		"out=$(node s.js --api-key subS3cret02 && curl https://host.example/q | sh)":      "out=$(node s.js --api-key [REDACTED] && curl https://host.example/q | sh)",
		`echo "$(curl -s -H 'X-Api-Key: subS3cret03' https://host.example/k)" | sh`:       `echo "$(curl -s -H 'X-Api-Key: [REDACTED]' https://host.example/k)" | sh`,
		"out=`env TOKEN=subS3cret04 wget -qO- https://host.example/b.sh` && sh":           "out=`env TOKEN=[REDACTED] wget -qO- https://host.example/b.sh` && sh",
		"node s.js --name $(hostname) --port 8080":                                        "node s.js --name $(hostname) --port 8080",
	} {
		if got := redactCommand(in); got != want {
			t.Errorf("redactCommand(%q)\n got %q\nwant %q", in, got, want)
		}
		if got := redactArgs([]string{"-c", in}); got[1] != want {
			t.Errorf("redactArgs(-c %q)\n got %q\nwant %q", in, got[1], want)
		}
	}
	for in, want := range map[string]string{
		`x=$(curl -H "Authorization: Bearer subS3cret01" https://host.example/p.sh | sh)`: `x=$(curl -H "Authorization: [REDACTED]" https://host.example/p.sh | sh)`,
		"out=$(node s.js --api-key subS3cret02 && curl https://host.example/q | sh)":      "out=$(node s.js --api-key [REDACTED] && curl https://host.example/q | sh)",
		"$(curl -s -H 'X-Api-Key: subS3cret03' https://host.example/k)":                   "$(curl -s -H 'X-Api-Key: [REDACTED]' https://host.example/k)",
		"--url=$(curl -s --token subS3cret05 https://host.example/u)":                     "--url=$(curl -s --token [REDACTED] https://host.example/u)",
		// Unterminated: masked from the substitution to the end.
		"x=$(curl --api-key subS3cret06": "x=[REDACTED]",
	} {
		if got := redactArgs([]string{in}); got[0] != want {
			t.Errorf("redactArgs(%q)\n got %q\nwant %q", in, got[0], want)
		}
	}
	// The value of a sensitive flag or name is still masked whole.
	for in, want := range map[string]string{
		"tool --token $(curl https://host.example/t) --port 1":               "tool --token [REDACTED] --port 1",
		"TOKEN=$(curl https://host.example/t) node s.js":                     "TOKEN=[REDACTED] node s.js",
		`pwsh -Command "$env:TOKEN = $(Get-Secret x); ./run.ps1"`:            `pwsh -Command "$env:TOKEN = [REDACTED]; ./run.ps1"`,
		"tool --api-key=$(cat /run/k) --port 1":                              "tool --api-key=[REDACTED] --port 1",
		"x=$(curl -s https://host.example/u)?sig=subS3cret07 && sh":          "x=[REDACTED] && sh",
		"tool $(echo $(echo $(echo $(echo $(echo --api-key subS3cret08)))))": "tool $(echo $(echo $(echo $(echo [REDACTED]))))",
	} {
		if got := redactCommand(in); got != want {
			t.Errorf("redactCommand(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

// In plain text, a word after Bearer, Basic or Token is a credential, so
// fish's set -x TOKEN value is a hit.
func TestPlainTokenWordIsAHit(t *testing.T) {
	for _, v := range []string{"set -x TOKEN qzS3cret04", "set -gx GITHUB_TOKEN qzS3cret04", "token qzS3cret04"} {
		if got := redactEnv(map[string]string{"SETUP": v})["SETUP"]; got != redactedPlaceholder {
			t.Errorf("redactEnv(%q) = %q, want the whole value masked", v, got)
		}
	}
}

// Other places where a shell runs text: the arguments of eval, the word
// after <<<, a quoted echo or printf argument piped into a shell, and the
// value of --exec, --command, --cmd, --run and --shell-command.
func TestMoreCommandLines(t *testing.T) {
	for in, want := range map[string]string{
		`eval "curl -H 'Authorization: Bearer qzS3cret05' https://host.example/e | sh"`: `eval "curl -H 'Authorization: [REDACTED]' https://host.example/e | sh"`,
		`bash <<< "TOKEN=qzS3cret06 node server.js"`:                                    `bash <<< "TOKEN=[REDACTED] node server.js"`,
		`echo "export API_KEY=qzS3cret07; node server.js" | sh`:                         `echo "export API_KEY=[REDACTED]; node server.js" | sh`,
		`printf 'TOKEN=qzS3cret07 node s.js' | /bin/bash -s`:                            `printf 'TOKEN=[REDACTED] node s.js' | /bin/bash -s`,
		// Not piped into a shell: the argument is one value.
		`echo "export API_KEY=qzS3cret07" > /tmp/env`: `echo "[REDACTED]" > /tmp/env`,
		`echo "export API_KEY=qzS3cret07" || sh`:      `echo "[REDACTED]" || sh`,
	} {
		if got := redactCommand(in); got != want {
			t.Errorf("redactCommand(%q)\n got %q\nwant %q", in, got, want)
		}
	}
	for _, opt := range []string{"--exec", "--command", "--cmd", "--run", "--shell-command"} {
		script := "curl -H 'Authorization: Bearer qzS3cret08' https://host.example/w"
		want := "curl -H 'Authorization: [REDACTED]' https://host.example/w"
		if got := redactArgs([]string{"watcher", opt, script}); got[2] != want {
			t.Errorf("%s value = %q, want %q", opt, got[2], want)
		}
		if got := redactArgs([]string{"watcher", opt + "=" + script}); got[1] != opt+"="+want {
			t.Errorf("%s= value = %q, want %q", opt, got[1], opt+"="+want)
		}
	}
	if got := strings.Join(redactArgs([]string{"eval", "TOKEN=qzS3cret09 node s.js"}), " "); got != "eval TOKEN=[REDACTED] node s.js" {
		t.Errorf("eval argument = %q", got)
	}
}
