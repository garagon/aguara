package scriptrisk

import "testing"

func TestURLUserinfoRedaction(t *testing.T) {
	for _, raw := range []string{"TOKEN", "user:", ":TOKEN", "user:part@TOKEN", "user%40TOKEN"} {
		in := "pip install --index-url http://" + raw + "@packages.example/@scope/x"
		want := "pip install --index-url http://[REDACTED]@packages.example/@scope/x"
		if got := redactURLCredentials(in); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}
