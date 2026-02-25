package update

import (
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
		name    string
		result  Result
		want    bool
	}{
		{"different versions", Result{Latest: "v0.4.0", Current: "v0.3.0"}, true},
		{"same version", Result{Latest: "v0.3.0", Current: "v0.3.0"}, false},
		{"dev version", Result{Latest: "v0.4.0", Current: "dev"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.result.NeedsUpdate())
		})
	}
}
