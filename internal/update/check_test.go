package update

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCheckLatest_UpdateAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/repos/garagon/aguara/releases/latest", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name": "v0.4.0"}`))
	}))
	defer srv.Close()

	r := checkLatestWithBase(srv.URL, "v0.3.0", "garagon/aguara")

	assert.NotNil(t, r)
	assert.Equal(t, "v0.4.0", r.Latest)
	assert.Equal(t, "v0.3.0", r.Current)
	assert.True(t, r.NeedsUpdate())
	assert.Contains(t, r.UpdateURL, "go install")
}

func TestCheckLatest_UpToDate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name": "v0.3.0"}`))
	}))
	defer srv.Close()

	r := checkLatestWithBase(srv.URL, "v0.3.0", "garagon/aguara")

	assert.NotNil(t, r)
	assert.False(t, r.NeedsUpdate())
}

func TestCheckLatest_DevVersion(t *testing.T) {
	r := CheckLatest("dev", "garagon/aguara")
	assert.Nil(t, r)
}

func TestCheckLatest_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name": "v0.4.0"}`))
	}))
	defer srv.Close()

	r := checkLatestWithBase(srv.URL, "v0.3.0", "garagon/aguara")
	assert.Nil(t, r)
}

func TestCheckLatest_NetworkError(t *testing.T) {
	r := checkLatestWithBase("http://127.0.0.1:1", "v0.3.0", "garagon/aguara")
	assert.Nil(t, r)
}

func TestCheckLatest_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	r := checkLatestWithBase(srv.URL, "v0.3.0", "garagon/aguara")
	assert.Nil(t, r)
}

func TestCheckLatest_EmptyTagName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name": ""}`))
	}))
	defer srv.Close()

	r := checkLatestWithBase(srv.URL, "v0.3.0", "garagon/aguara")
	assert.Nil(t, r)
}

func TestCheckLatest_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	r := checkLatestWithBase(srv.URL, "v0.3.0", "garagon/aguara")
	assert.Nil(t, r)
}

func TestNeedsUpdate(t *testing.T) {
	tests := []struct {
		name   string
		result Result
		want   bool
	}{
		{"different versions", Result{Latest: "v0.4.0", Current: "v0.3.0"}, true},
		{"same version", Result{Latest: "v0.3.0", Current: "v0.3.0"}, false},
		{"dev version", Result{Latest: "v0.4.0", Current: "dev"}, false},
		// The binary's ldflag version comes in without the "v" prefix
		// ("0.14.2") while GitHub returns the tag ("v0.14.2"). Before
		// normalization these compared unequal and NeedsUpdate returned
		// true for every binary on every invocation.
		{"v-prefix mismatch same version", Result{Latest: "v0.14.2", Current: "0.14.2"}, false},
		{"v-prefix mismatch different version", Result{Latest: "v0.14.3", Current: "0.14.2"}, true},
		{"both without v, same", Result{Latest: "0.14.2", Current: "0.14.2"}, false},
		{"both with v, same", Result{Latest: "v0.14.2", Current: "v0.14.2"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.result.NeedsUpdate())
		})
	}
}

// TestCheckLatest_RejectsBadTagShape verifies that the update check
// refuses tag_name values that aren't well-formed semver. A hijacked or
// typosquatted release page can't surface arbitrary text in the user's
// terminal via the update notice this way.
func TestCheckLatest_RejectsBadTagShape(t *testing.T) {
	badTags := []string{
		"main",                               // branch-like
		"latest",                             // floating alias
		"v1",                                 // major-only, force-pushed
		"v0.14",                              // missing patch
		"0.14.2",                             // missing v prefix
		"v0.14.2-rc1",                        // prerelease suffix not accepted
		"v0.14.2+build",                      // build metadata not accepted
		"<script>alert(1)</script>",          // hostile
		"v0.14.2; rm -rf /",                  // command injection
		"go install github.com/evil/pkg@v1",  // typosquat via tag text
	}
	for _, tag := range badTags {
		t.Run("reject_"+tag, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"tag_name": ` + toJSONString(tag) + `}`))
			}))
			defer srv.Close()

			r := checkLatestWithBase(srv.URL, "v0.14.2", "garagon/aguara")
			assert.Nil(t, r, "should reject tag %q", tag)
		})
	}
}

// toJSONString is a minimal JSON string encoder for test fixtures.
func toJSONString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
