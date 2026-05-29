package commands

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/garagon/aguara/internal/intel"
	"github.com/garagon/aguara/internal/intel/bundle"
)

// intelInsecureEnv must be set to "1" alongside the --insecure-intel flag
// to disable signature verification of the advisory bundle. Requiring both
// the flag and the env var makes it hard to trip accidentally from a CI
// arg, and it is never sourced from config.
const intelInsecureEnv = "AGUARA_INSECURE_INTEL"

// resolveInsecureIntel validates the --insecure-intel opt-out. It returns
// true only when BOTH the flag and intelInsecureEnv=1 are present, and
// emits a stderr warning on every such run. A flag set without the env var
// is a hard error rather than a silent downgrade.
func resolveInsecureIntel(flag bool) (bool, error) {
	if !flag {
		return false, nil
	}
	if os.Getenv(intelInsecureEnv) != "1" {
		return false, fmt.Errorf("--insecure-intel also requires %s=1 in the environment; it disables advisory-bundle signature verification and is only for mirrors, air-gapped hosts, and tests", intelInsecureEnv)
	}
	fmt.Fprintf(os.Stderr, "WARNING: --insecure-intel: advisory-bundle signature/identity verification is DISABLED (manifest and blob digests are still checked). Do not use in production.\n")
	return true, nil
}

// fetchVerifiedSnapshot is the single trust-root path shared by
// `aguara update`, `check --fresh`, and `audit --fresh`: fetch the signed
// advisory bundle from baseURL and return the decoded snapshot. It never
// returns a snapshot that failed verification.
//
// With insecure=false (default) it verifies the Sigstore signature and
// pinned publisher identity, then validates the manifest against the blob.
// With insecure=true it skips only the signature/identity step; the
// manifest/blob content checks (schema, name, sizes, digests, decode)
// still run.
func fetchVerifiedSnapshot(ctx context.Context, baseURL string, insecure bool) (intel.Snapshot, error) {
	get := func(name string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/"+name, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "aguara-update/1.0 (+https://github.com/garagon/aguara)")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", name, err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetch %s: http %d %s", name, resp.StatusCode, resp.Status)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, intel.MaxHTTPBodyBytes+1))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		if int64(len(data)) > intel.MaxHTTPBodyBytes {
			return nil, fmt.Errorf("%s exceeds %d byte cap", name, intel.MaxHTTPBodyBytes)
		}
		return data, nil
	}

	manifest, err := get("generated_intel.meta.json")
	if err != nil {
		return intel.Snapshot{}, err
	}
	blob, err := get(bundle.ExpectedBlobName)
	if err != nil {
		return intel.Snapshot{}, err
	}
	if insecure {
		// The signing bundle is not needed when signature verification
		// is disabled.
		return bundle.DecodeUnverified(manifest, blob)
	}
	bundleBytes, err := get("generated_intel.meta.json.bundle")
	if err != nil {
		return intel.Snapshot{}, err
	}
	return bundle.VerifyAndDecode(manifest, bundleBytes, blob)
}
