package commands

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/incident"
	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

func TestInsecureUpdateDoesNotEstablishVerifiedCache(t *testing.T) {
	resetFlags()
	t.Cleanup(resetFlags)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(intelInsecureEnv, "1")
	prev := intelBundleBaseURL
	intelBundleBaseURL = serveBundleBadSignature(t)
	t.Cleanup(func() { intelBundleBaseURL = prev; rootCmd.SetArgs(nil) })
	out := filepath.Join(t.TempDir(), "update.json")
	rootCmd.SetArgs([]string{"update", "--insecure-intel", "--format", "json", "-o", out})
	require.NoError(t, rootCmd.Execute())
	s := &intel.Store{Dir: filepath.Join(home, ".aguara", "intel")}
	_, err := s.LoadVerified()
	require.Error(t, err, "bypassed signature must not become trusted local intel")
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	var report updateOutput
	require.NoError(t, json.Unmarshal(data, &report))
	require.False(t, report.Verified)
	require.Nil(t, localOrEmbeddedOverride(s))
}

func TestInsecureFreshCacheCannotBeReusedByDefaultOrStale(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(intelInsecureEnv, "1")
	require.NoError(t, runCheckFresh(t, t.TempDir(), serveBundleBadSignature(t), "--insecure-intel"))
	data, err := os.ReadFile(flagOutput)
	require.NoError(t, err)
	var report incident.CheckResult
	require.NoError(t, json.Unmarshal(data, &report))
	require.Equal(t, "remote-unverified", report.Intel.Snapshot)
	s := &intel.Store{Dir: filepath.Join(home, ".aguara", "intel")}
	require.Nil(t, localOrEmbeddedOverride(s), "default check must not reuse unsigned intel")
	require.Error(t, runCheckFresh(t, t.TempDir(), serveBundleBadSignature(t), "--allow-stale"))
}

func TestInsecureAuditProvenance(t *testing.T) {
	resetFlags()
	t.Cleanup(resetFlags)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(intelInsecureEnv, "1")
	dir := t.TempDir()
	writeBenignNPM(t, dir)
	prev := intelBundleBaseURL
	intelBundleBaseURL = serveBundleBadSignature(t)
	t.Cleanup(func() { intelBundleBaseURL = prev; rootCmd.SetArgs(nil) })
	out := filepath.Join(t.TempDir(), "audit.json")
	rootCmd.SetArgs([]string{"audit", dir, "--fresh", "--insecure-intel", "--format", "json", "-o", out})
	require.NoError(t, rootCmd.Execute())
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	var report AuditResult
	require.NoError(t, json.Unmarshal(data, &report))
	require.Equal(t, "remote-unverified", report.Intel.Snapshot)
	require.Equal(t, report.Intel.Snapshot, report.Check.Intel.Snapshot)
	s := &intel.Store{Dir: filepath.Join(home, ".aguara", "intel")}
	_, err = s.LoadVerified()
	require.Error(t, err)
}

func TestIntelFetchVerificationStatusAndContentChecks(t *testing.T) {
	t.Setenv(intelInsecureEnv, "1")
	insecure, err := resolveInsecureIntel(false)
	require.NoError(t, err)
	require.False(t, insecure, "env alone is not authorization")
	_, err = fetchIntelSnapshot(context.Background(), serveBundleBadSignature(t), insecure)
	require.Error(t, err)
	_, err = fetchIntelSnapshot(context.Background(), serveSignedBundle(t, true), true)
	require.Error(t, err, "bypass must not skip content integrity")
	fetched, err := fetchIntelSnapshot(context.Background(), serveSignedBundle(t, false), false)
	require.NoError(t, err)
	require.True(t, fetched.Verified)
	s := &intel.Store{Dir: t.TempDir()}
	require.NoError(t, fetched.save(s))
	_, err = s.LoadVerified()
	require.NoError(t, err)
}

func TestUnverifiedUpdateTerminalIsExplicit(t *testing.T) {
	resetFlags()
	t.Cleanup(resetFlags)
	out := captureStdoutBytes(t, func() {
		require.NoError(t, writeUpdateOutput(intel.Snapshot{}, t.TempDir(), false))
	})
	require.Contains(t, string(out), "UNVERIFIED")
	require.NotContains(t, string(out), "(verified signed bundle)")
	require.Contains(t, intelSourceLabel("remote-unverified"), "UNVERIFIED")
}
