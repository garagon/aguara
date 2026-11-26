package discover

import "testing"

// A command given as one string is redacted in place: tokens that change
// keep their original quoting, or get single quotes, so the displayed
// command means the same; an unterminated quote masks everything from the
// quote to the end.
func TestRedactCommandKeepsQuoting(t *testing.T) {
	for in, want := range map[string]string{
		`docker run --rm -e "DB_PASS=s3cret" ghcr.io/acme/mcp:1.2`:         `docker run --rm -e "DB_PASS=[REDACTED]" ghcr.io/acme/mcp:1.2`,
		`docker run -e 'API_KEY=s3cret' image`:                             `docker run -e 'API_KEY=[REDACTED]' image`,
		`env API_TOKEN=s3cret node server.js`:                              `env 'API_TOKEN=[REDACTED]' node server.js`,
		`sh -c 'curl -H "Authorization: Bearer s3cret" https://x.example'`: `sh -c 'curl -H "Authorization: Bearer [REDACTED]" https://x.example'`,
		`tool --token  s3cret   --mode fast`:                               `tool --token  '[REDACTED]'   --mode fast`,
		`env NODE_ENV=production node server.js`:                           `env NODE_ENV=production node server.js`,
		`env TOKEN="s3cret and more`:                                       `env TOKEN=[REDACTED]`,
		`node server.js --token 's3cret`:                                   `node server.js --token [REDACTED]`,
		`echo ok "s3cret`:                                                  `echo ok [REDACTED]`,
		`node server.js --api-key s3cret\`:                                 `node server.js --api-key [REDACTED]`,
	} {
		if got := redactCommand(in); got != want {
			t.Errorf("redactCommand(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}
