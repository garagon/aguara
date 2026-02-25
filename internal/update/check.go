package update

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Result holds the outcome of a version check.
type Result struct {
	Latest    string // e.g. "v0.4.0"
	Current   string
	UpdateURL string // "go install github.com/garagon/aguara/cmd/aguara@latest"
}

// NeedsUpdate returns true if Latest differs from Current and Current is not "dev".
func (r *Result) NeedsUpdate() bool {
	return r.Latest != r.Current && r.Current != "dev"
}

// githubRelease is the minimal JSON shape we need from the GitHub API.
type githubRelease struct {
	TagName string `json:"tag_name"`
}

// defaultBaseURL is the GitHub API base URL, overridable for testing.
var defaultBaseURL = "https://api.github.com"

// CheckLatest queries GitHub Releases API for the latest release of repo
// (e.g. "garagon/aguara"). Returns nil on timeout, network failure, or
// non-release versions. Never returns an error to the caller.
func CheckLatest(currentVersion, repo string) *Result {
	if currentVersion == "dev" {
		return nil
	}
	return checkLatestWithBase(defaultBaseURL, currentVersion, repo)
}

func checkLatestWithBase(baseURL, currentVersion, repo string) *Result {
	url := fmt.Sprintf("%s/repos/%s/releases/latest", baseURL, repo)

	client := &http.Client{Timeout: 1 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil
	}

	if release.TagName == "" {
		return nil
	}

	return &Result{
		Latest:    release.TagName,
		Current:   currentVersion,
		UpdateURL: fmt.Sprintf("go install github.com/%s/cmd/aguara@latest", repo),
	}
}
