package discover

import (
	"strings"
	"testing"
)

// countBackstops counts the backstop firings while f runs.
func countBackstops(t *testing.T, f func()) []string {
	t.Helper()
	var fired []string
	onBackstop = func(text string) { fired = append(fired, text) }
	defer func() { onBackstop = nil }()
	f()
	return fired
}

// Pairs that are not shell syntax (Name: value, Token value, NAME = value)
// are found by the word rules in every command-line context.
func TestNonShellPairsInCommandLines(t *testing.T) {
	const secret = "qzS3cretA1"
	for _, form := range []string{"password: " + secret, "X-Api-Key: " + secret, "Token " + secret, "API_KEY = " + secret, "Authorization: Bearer " + secret, "Authorization: Token " + secret, "API_KEY =" + secret} {
		line := "login " + form + " --verbose"
		outs := map[string]string{
			"command":     redactCommand(line),
			"-c script":   redactArgs([]string{"-c", line})[1],
			"--exec":      redactArgs([]string{"--exec", line})[1],
			"eval":        redactCommand(`eval "` + line + `"`),
			"here-string": redactCommand(`bash <<< "` + line + `"`),
			"echo | sh":   redactCommand(`echo "` + line + `" | sh`),
			"$( )":        redactCommand("x=$(" + line + ")"),
		}
		for where, out := range outs {
			if p := showsPiece(out, secret); p != "" {
				t.Errorf("%s: %q: %q shown in %q", where, form, p, out)
			}
			if !strings.Contains(out, "login ") || !strings.Contains(out, " --verbose") {
				t.Errorf("%s: %q: the command around the secret changed: %q", where, form, out)
			}
		}
	}
	for in, want := range map[string]string{
		"login password: qzS3cretA1 --verbose":             "login password: [REDACTED] --verbose",
		"login Token qzS3cretA1 --verbose":                 "login Token [REDACTED] --verbose",
		"login API_KEY = qzS3cretA1 --verbose":             "login API_KEY = [REDACTED] --verbose",
		"login Authorization: Bearer qzS3cretA1 --verbose": "login Authorization: Bearer [REDACTED] --verbose",
		"login TOKEN= qzS3cretA1 --verbose":                "login TOKEN= [REDACTED] --verbose",
		"docker run -e GITHUB_TOKEN ghcr.io/github/server": "docker run -e GITHUB_TOKEN ghcr.io/github/server",
	} {
		if got := redactCommand(in); got != want {
			t.Errorf("redactCommand(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

// A word after an authorization scheme is a credential unless it is an
// option (--hostname) or the "=" of a pair (TOKEN = x), in plain values and
// in command lines alike; a credential that starts with "--" or "==" is
// still one.
func TestAuthSchemeCredentialsAndOptions(t *testing.T) {
	for _, v := range []string{"Token --qzS3cretB1", "token\t--qzS3cretB1", "Basic ==qzS3cretB1", "Bearer --Xa9_qzS3cretB1"} {
		if got := redactValue(v); got != redactedPlaceholder {
			t.Errorf("redactValue(%q) = %q, want the whole value masked", v, got)
		}
		if got := redactCommand("curl -H Authorization: " + v + " https://x.example/a"); showsPiece(got, "qzS3cretB1") != "" {
			t.Errorf("command with %q = %q", v, got)
		}
	}
	for in, want := range map[string]string{
		"gh auth token --hostname github.com":    "gh auth token --hostname github.com",
		"tool Bearer --Xa9_qzS3cretB1 --verbose": "tool Bearer [REDACTED] --verbose",
		"tool Token --qzS3cretB1 --verbose":      "tool Token [REDACTED] --verbose",
		"tool TOKEN = qzS3cretB1 --verbose":      "tool TOKEN = [REDACTED] --verbose",
	} {
		var got string
		fired := countBackstops(t, func() { got = redactCommand(in) })
		if got != want || len(fired) != 0 {
			t.Errorf("redactCommand(%q) = %q (backstop %d), want %q", in, got, len(fired), want)
		}
	}
	if got := redactValue("gh auth token --hostname github.com"); got != "gh auth token --hostname github.com" {
		t.Errorf("an option after token is not a credential: %q", got)
	}
}

// A here-string is a command line only for a shell; for any other program
// it is one plain value.
func TestHereStringOnlyToAShell(t *testing.T) {
	for in, want := range map[string]string{
		`cat <<< "TOKEN=ab;qzS3cretA2"`:              `cat <<< "[REDACTED]"`,
		`grep x <<< "API_KEY=ab qzS3cretA3"`:         `grep x <<< "[REDACTED]"`,
		`bash <<< "TOKEN=qzS3cretA3 node server.js"`: `bash <<< "TOKEN=[REDACTED] node server.js"`,
		`cat <<< "hello world"`:                      `cat <<< "hello world"`,
	} {
		if got := redactCommand(in); got != want {
			t.Errorf("redactCommand(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

// Of the long options, only --exec is known to take a shell command line;
// the value of --command, --cmd, --run and --shell-command is one value.
func TestOnlyExecTakesACommandLine(t *testing.T) {
	for _, opt := range []string{"--command", "--cmd", "--run", "--shell-command"} {
		value := "login --password p&ssqzS3cretA4"
		if got := redactArgs([]string{"tool", opt, value}); got[2] != redactedPlaceholder {
			t.Errorf("%s value = %q, want it masked whole", opt, got[2])
		}
		if got := redactArgs([]string{"tool", opt + "=" + value}); got[1] != opt+"="+redactedPlaceholder {
			t.Errorf("%s= value = %q, want it masked whole", opt, got[1])
		}
	}
	if got := redactArgs([]string{"watcher", "--exec", "login --password qzS3cretA4 && echo ok"}); got[2] != "login --password [REDACTED] && echo ok" {
		t.Errorf("--exec value = %q", got[2])
	}
}

// Command mode never shows what plain mode would mask: when a simple
// command still has a hit after the word rules, it is masked from its first
// argument to its end, and the other commands of the line stay visible.
func TestBackstopMasksTheSimpleCommand(t *testing.T) {
	// fish's set NAME value is not a word rule (set -x TOKEN value is, through
	// the word after Token), so the backstop masks it.
	for in, want := range map[string]string{
		`fish -c "set -gx GITHUB_TOKEN qzS3cretA5; node s.js"`:             `fish -c "set [REDACTED]; node s.js"`,
		"set -gx GITHUB_TOKEN qzS3cretA5 && curl https://x.example/i | sh": "set [REDACTED] && curl https://x.example/i | sh",
	} {
		var got string
		fired := countBackstops(t, func() { got = redactCommand(in) })
		if got != want {
			t.Errorf("redactCommand(%q)\n got %q\nwant %q", in, got, want)
		}
		if len(fired) != 1 {
			t.Errorf("backstop fired %d times for %q", len(fired), in)
		}
	}
	// In an argument list the arguments from the first one the hit needs
	// (here set) to the end are masked, so the leading arguments stay
	// visible.
	if got := redactArgs([]string{"set", "-x", "GITHUB_TOKEN", "qzS3cretA5"}); strings.Join(got, " ") != "[REDACTED] [REDACTED] [REDACTED] [REDACTED]" {
		t.Errorf("argument list = %q", got)
	}
	if got := redactArgs([]string{"-y", "@scope/pkg", "set", "-gx", "GITHUB_TOKEN", "qzS3cretA5", "--verbose"}); strings.Join(got, " ") != "-y @scope/pkg [REDACTED] [REDACTED] [REDACTED] [REDACTED] [REDACTED]" {
		t.Errorf("argument list = %q", got)
	}
	if got := redactArgs([]string{"-y", "@scope/pkg", `{"token": "qzS3cretA5"`}); strings.Join(got, " ") != "-y @scope/pkg [REDACTED]" {
		t.Errorf("argument list = %q", got)
	}
	if got := redactCommand(`fish -c "set -x TOKEN qzS3cretA5; node s.js"`); got != `fish -c "set -x TOKEN [REDACTED]; node s.js"` {
		t.Errorf("set -x TOKEN = %q", got)
	}
}

// The guarantee itself: a value that plain mode masks shows no piece of its
// secret when it is run as a command line, in any command-line context.
// The values whose secret holds a blank or an operator a shell reads as the
// end of a word are left out: there the text after it is another word or
// command for the shell, exactly as in TestRedactionKeepsEveryNonSecretToken,
// which requires that text to stay visible.
func TestCommandModeNeverShowsWhatPlainModeMasks(t *testing.T) {
	quote := func(v string) string { return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'" }
	cases := 0
	forEachSecretValue(func(v string, split bool) {
		if split || redactValue(v) == v {
			return
		}
		cases++
		outs := map[string]string{
			"sh -c":       redactArgs([]string{"-c", v})[1],
			"--exec":      redactArgs([]string{"--exec", v})[1],
			"eval":        redactArgs([]string{"eval", v})[1],
			"bash <<<":    redactCommand("bash <<< " + quote(v)),
			"echo | sh":   redactCommand("echo " + quote(v) + " | sh"),
			"$( ) string": redactCommand("x=$(" + v + ")"),
			"$( ) arg":    redactArgs([]string{"x=$(" + v + ")"})[0],
		}
		for where, out := range outs {
			if p := showsPiece(out, secretMarker); p != "" {
				t.Errorf("%s: %q shown\n in %q\nout %q", where, p, v, out)
			}
		}
	})
	if cases < 1500 {
		t.Fatalf("only %d generated values", cases)
	}
}

// Ordinary commands are shown as written and never reach the backstop.
func TestBackstopQuietOnOrdinaryCommands(t *testing.T) {
	samples := []string{
		"npx -y @modelcontextprotocol/server-github",
		"docker run -i --rm -e GITHUB_PERSONAL_ACCESS_TOKEN ghcr.io/github/github-mcp-server",
		"uvx mcp-server-fetch --ignore-robots-txt",
		"node /opt/mcp/build/index.js --port 8080 --log-level debug",
		"sh -c 'cd /app && exec npm start'",
		"bash -lc 'source ~/.nvm/nvm.sh && nvm use 20 && node server.js'",
		"python -m mcp_server_time --local-timezone America/New_York",
		"env NODE_ENV=production PORT=3000 node dist/index.js",
		"sh -c 'exec node /app/server.js >> /var/log/mcp.log 2>&1'",
		"cmd /c npx -y @playwright/mcp@latest",
		`pwsh -Command "& { ./start.ps1 -Port 8080 }"`,
		"docker run --rm -i -v /home/u/.config:/config mcp/fs /config",
		`npx -y mcp-remote https://mcp.example.com/sse --header "Accept: text/event-stream"`,
		"uv run --with mcp mcp run server.py",
		"node --require ./tracing.js server.js",
		"curl -fsSL https://get.example.com/install.sh | sh -s -- --version 1.2.3",
		"ssh -i ~/.ssh/id_ed25519 deploy@host.example.com mcp-server",
		"java -Xmx512m -jar /opt/server.jar --spring.profiles.active=prod",
		"deno run --allow-net --allow-read jsr:@example/mcp",
		"bun x @example/mcp --stdio",
		"go run ./cmd/server -addr :8080",
		"aws sts get-session-token --duration-seconds 900",
		"gh auth status",
		"git -C /srv/repo pull --ff-only && make -C /srv/repo run",
		`sh -c 'x=$(date +%s); echo "started $x" >> /tmp/mcp.log; exec node s.js'`,
		`bash -c "export PATH=$HOME/.local/bin:$PATH && uvx mcp-server-git --repository /repo"`,
		"watchexec --exec 'npm run build' -w src",
		`echo "node server.js" | sh`,
		`bash <<< "cd /app && node server.js"`,
		`eval "$(fnm env) && node server.js"`,
		"kubectl port-forward svc/mcp 8080:80",
		"mcp-proxy --sse-port 8096 -- uvx mcp-server-fetch",
		"docker compose -f /srv/mcp/compose.yaml up",
		"npm exec --yes -- @example/server --config ./config.json",
		"nohup node server.js > /dev/null 2>&1 &",
		`python3 -c "import mcp_server; mcp_server.main()"`,
		"sudo -u mcp /usr/local/bin/mcp-server --listen 127.0.0.1:9000",
		"redis-server --port 6380 --appendonly yes",
		"psql -h db.internal -U app -d app -c 'select 1'",
		"terraform plan -var region=eu-west-1",
	}
	for _, s := range samples {
		var got string
		fired := countBackstops(t, func() { got = redactCommand(s) })
		if len(fired) != 0 {
			t.Errorf("backstop fired on %q: %q", s, fired)
		}
		if got != s {
			t.Errorf("redactCommand(%q) = %q, want it unchanged", s, got)
		}
		args := strings.Fields(s)[1:]
		fired = countBackstops(t, func() { redactArgs(args) })
		if len(fired) != 0 {
			t.Errorf("backstop fired on the argument list of %q: %q", s, fired)
		}
	}
}

// A secret split across arguments, whose hit exists only once they are
// joined, is masked from the first argument the hit needs; the arguments
// before it stay visible.
func TestArgumentListSplitSecrets(t *testing.T) {
	ph := redactedPlaceholder
	for _, tc := range []struct{ in, want []string }{
		{[]string{"-y", "@acme/pkg", "https://user:Sk9a", "ZZq@h.example/x"}, []string{"-y", "@acme/pkg", ph, ph}},
		{[]string{"--url", "postgres://user:Sk10", "pass@db.example/app"}, []string{"--url", ph, ph}},
		{[]string{"-y", "@acme/pkg", "https://user:Sk", "9aZZ", "q@h.example/x"}, []string{"-y", "@acme/pkg", ph, ph, ph}},
	} {
		if got := redactArgs(tc.in); strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") {
			t.Errorf("redactArgs(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	// Generated: secret-bearing values split at every position into two
	// and three arguments, after ordinary arguments.
	const marker = "Qx7mZp4Wr9Kv"
	values := []string{
		"https://user:" + marker + "@h.example/x",
		"postgres://app:" + marker + "@db.example/app",
		`{"token": "` + marker + `"}`,
		"Authorization: Bearer " + marker,
		"--api-key " + marker,
		"API_KEY=" + marker,
		"X-Api-Key: " + marker,
		"https://x.example/sse?sig=" + marker,
		"set -gx GITHUB_TOKEN " + marker,
		"Token --" + marker,
	}
	lead := []string{"-y", "@acme/pkg", "--port", "8080"}
	check := func(pieces []string) bool {
		// Only splits whose hit exists once the pieces are joined and that
		// no word rule handles: a piece with a hit of its own is masked by
		// the word rules, and when a word rule takes a piece as a whole
		// value (--api-key, then " Q"), the pieces after it are separate
		// arguments, as words after a separator are in a command line.
		if !plainHit(strings.Join(pieces, " ")) {
			return false
		}
		for _, p := range pieces {
			if plainHit(p) {
				return false
			}
		}
		args := append(append([]string{}, lead...), pieces...)
		words, _ := redactArgsAt(args, 0)
		if strings.Join(words, "\x00") != strings.Join(args, "\x00") {
			return false
		}
		out := redactArgs(args)
		if p := showsPiece(strings.Join(out, " "), marker); p != "" {
			t.Errorf("%q shown in %q for %q", p, out, args)
		}
		if strings.Join(out[:len(lead)], " ") != strings.Join(lead, " ") {
			t.Errorf("leading arguments changed: %q for %q", out, args)
		}
		return true
	}
	cases := 0
	for _, v := range values {
		for i := 1; i < len(v); i++ {
			if check([]string{v[:i], v[i:]}) {
				cases++
			}
			for j := i + 1; j < len(v); j++ {
				if check([]string{v[:i], v[i:j], v[j:]}) {
					cases++
				}
			}
		}
	}
	if cases < 500 {
		t.Fatalf("only %d split lists checked", cases)
	}
}
