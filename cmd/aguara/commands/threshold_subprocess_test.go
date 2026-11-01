package commands

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const thresholdExitMarker = "AGUARA_TEST_THRESHOLD_EXCEEDED"

// Reuse the test binary, including its race instrumentation when enabled, rather
// than compiling another copy of this package inside an already-running suite.
func requireThresholdSubprocess(t *testing.T, helper, fixtureEnv string) {
	t.Helper()
	binary, err := os.Executable()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test.run=^"+helper+"$", "-test.parallel=1", "-test.timeout=60s")
	// Helpers deliberately exit before their cleanup callbacks. The parent owns
	// their temporary files so a successful exit-code assertion cannot leak them.
	temp := t.TempDir()
	cmd.Env = append(os.Environ(), fixtureEnv, "TMPDIR="+temp, "TMP="+temp, "TEMP="+temp)
	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "helper timed out: %s", out)
	var exit *exec.ExitError
	require.ErrorAs(t, err, &exit, "expected threshold exit: %s", out)
	require.Equal(t, 1, exit.ExitCode(), "unexpected helper exit: %s", out)
	require.Contains(t, string(out), thresholdExitMarker, "a crash or unrelated test failure is not a threshold exit")
}

func exitAtThreshold(t *testing.T, err error) {
	t.Helper()
	require.ErrorIs(t, err, ErrThresholdExceeded)
	fmt.Println(thresholdExitMarker)
	os.Exit(1)
}
