package update

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Result holds the outcome of a version check.
type Result struct {
	Latest    string // e.g. "v0.4.0"
	Current   string
	UpdateURL string // "go install github.com/garagon/aguara/cmd/aguara@latest"
}

// semverTag matches a well-formed release tag like v0.14.2 or v1.2.3.
var semverTag = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// normalizeVersion strips a leading "v" so comparisons tolerate the
// ldflags-stripped binary version ("0.14.2") against the GitHub tag
// ("v0.14.2"). Inputs that aren't plain semver are returned unchanged
// so caller-side equality still works for edge cases like "dev".
func normalizeVersion(s string) string {
	return strings.TrimPrefix(s, "v")
}

// NeedsUpdate returns true if Latest and Current refer to different
// releases. Both are normalized to strip the leading "v" so the binary's
// ldflag-injected version (without "v") compares cleanly against the
// GitHub tag (with "v"). Dev builds never report an update.
func (r *Result) NeedsUpdate() bool {
	if r.Current == "dev" {
		return false
	}
	return normalizeVersion(r.Latest) != normalizeVersion(r.Current)
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
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil
	}

	// Validate the returned tag shape. The GitHub response is authenticated
	// by TLS, but defense-in-depth: only accept well-formed semver tags so a
	// typo-squatted or hijacked release can't surface arbitrary text in the
	// user's terminal via the update notice.
	if !semverTag.MatchString(release.TagName) {
		return nil
	}

	return &Result{
		Latest:    release.TagName,
		Current:   currentVersion,
		UpdateURL: fmt.Sprintf("go install github.com/%s/cmd/aguara@latest", repo),
	}
}
