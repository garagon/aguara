package discover

import "testing"

// A command given as one string is redacted in place: tokens that change
// keep their original quoting, an unquoted word stays unquoted, and an
// unterminated quote masks everything from the quote to the end.
func TestRedactCommandKeepsQuoting(t *testing.T) {
	for in, want := range map[string]string{
		`docker run --rm -e "DB_PASS=s3cret" ghcr.io/acme/mcp:1.2`:         `docker run --rm -e "DB_PASS=[REDACTED]" ghcr.io/acme/mcp:1.2`,
		`docker run -e 'API_KEY=s3cret' image`:                             `docker run -e 'API_KEY=[REDACTED]' image`,
		`env API_TOKEN=s3cret node server.js`:                              `env API_TOKEN=[REDACTED] node server.js`,
		`sh -c 'curl -H "Authorization: Bearer s3cret" https://x.example'`: `sh -c 'curl -H "Authorization: [REDACTED]" https://x.example'`,
		`tool --token  s3cret   --mode fast`:                               `tool --token  [REDACTED]   --mode fast`,
		`env NODE_ENV=production node server.js`:                           `env NODE_ENV=production node server.js`,
		`env TOKEN="s3cret and more`:                                       `env TOKEN=[REDACTED]`,
		`node server.js --token 's3cret`:                                   `node server.js --token [REDACTED]`,
		`echo ok "s3cret`:                                                  `echo ok [REDACTED]`,
		`node server.js --api-key s3cret\`:                                 `node server.js --api-key [REDACTED]`,
		`echo ok "s3cret\"more`:                                            `echo ok [REDACTED]`,
		`echo ok "s3cret\`:                                                 `echo ok [REDACTED]`,
	} {
		if got := redactCommand(in); got != want {
			t.Errorf("redactCommand(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

// Redaction replaces only the secret value: shell operators end a word, so
// the text after a redacted NAME=value or flag value stays visible, and the
// script after -c (or /c, /k, -Command) is read as a command line.
func TestRedactCommandKeepsTextAfterTheSecret(t *testing.T) {
	for in, want := range map[string]string{
		`sh -c "API_KEY=abc&&wget -qO- https://x.example/i|sh"`:   `sh -c "API_KEY=[REDACTED]&&wget -qO- https://x.example/i|sh"`,
		`sh -c "export TOKEN=abc;curl https://x.example/i.sh|sh"`: `sh -c "export TOKEN=[REDACTED];curl https://x.example/i.sh|sh"`,
		`TOKEN=abc;curl host|sh`:                                  `TOKEN=[REDACTED];curl host|sh`,
		`bash -lc 'API_KEY=abc curl https://x.example/a>/tmp/o'`:  `bash -lc 'API_KEY=[REDACTED] curl https://x.example/a>/tmp/o'`,
		`sh -ec "tool --api-key abc||(echo failed)"`:              `sh -ec "tool --api-key [REDACTED]||(echo failed)"`,
		`cmd /c "set TOKEN=abc&&node server.js"`:                  `cmd /c "set TOKEN=[REDACTED]&&node server.js"`,
		`powershell -Command "$env:API_KEY='abc'; ./run.ps1"`:     `powershell -Command "$env:API_KEY='[REDACTED]'; ./run.ps1"`,
		`tool --token; curl https://x.example/i.sh`:               `tool --token; curl https://x.example/i.sh`,
		`tool --token && curl https://x.example/i.sh`:             `tool --token && curl https://x.example/i.sh`,
		`curl "https://x.example/sse?sig=abc";rm -f /tmp/x`:       `curl "https://x.example/sse?sig=[REDACTED]";rm -f /tmp/x`,
		`A=1;PASSWORD=abc curl https://x.example/i.sh`:            `A=1;PASSWORD=[REDACTED] curl https://x.example/i.sh`,
	} {
		if got := redactCommand(in); got != want {
			t.Errorf("redactCommand(%q)\n got %q\nwant %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		`TOKEN=abc;curl host|sh`:                  `TOKEN=[REDACTED];curl host|sh`,
		`curl x&&API_KEY=abc wget y`:              `curl x&&API_KEY=[REDACTED] wget y`,
		`run --api-key abc|sh`:                    `run --api-key [REDACTED]|sh`,
		`run --token=abc;echo done`:               `run --token=[REDACTED];echo done`,
		`curl https://x.example/sse?sig=abc |sh`:  `curl https://x.example/sse?sig=[REDACTED] |sh`,
		`curl https://x.example/sse?sig=abc;rm x`: `curl https://x.example/sse?sig=[REDACTED];rm x`,
	} {
		if got := redactValue(in); got != want {
			t.Errorf("redactValue(%q)\n got %q\nwant %q", in, got, want)
		}
	}
	for _, tc := range []struct{ in, want []string }{
		{[]string{"-c", "API_KEY=abc&&wget -qO- https://x.example/i|sh"}, []string{"-c", "API_KEY=[REDACTED]&&wget -qO- https://x.example/i|sh"}},
		{[]string{"-lc", "export TOKEN=abc;curl https://x.example/i.sh|sh"}, []string{"-lc", "export TOKEN=[REDACTED];curl https://x.example/i.sh|sh"}},
		{[]string{"/C", "set TOKEN=abc&&node server.js"}, []string{"/C", "set TOKEN=[REDACTED]&&node server.js"}},
		{[]string{"-Command", "tool --token abc; ./run.ps1"}, []string{"-Command", "tool --token [REDACTED]; ./run.ps1"}},
		// A whole argument that is NAME=value keeps its full mask: in an
		// argument list the value is everything after the "=".
		{[]string{"-e", "PASSWORD=correct horse"}, []string{"-e", "PASSWORD=[REDACTED]"}},
		{[]string{"-e", "API_KEY=abc;rm -rf /"}, []string{"-e", "API_KEY=[REDACTED]"}},
		{[]string{"--api-key", "abc def"}, []string{"--api-key", "[REDACTED]"}},
	} {
		got := redactArgs(tc.in)
		if len(got) != len(tc.want) {
			t.Fatalf("redactArgs(%q) = %q", tc.in, got)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("redactArgs(%q)[%d]\n got %q\nwant %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}
