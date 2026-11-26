//go:build unix

package aguara_test

import (
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/garagon/aguara"
)

// A rules-directory entry named *.yaml that is a named pipe, or a link to
// an endless device, used to block NewScanner forever or read without
// bound. Both are invalid_rule configuration problems now.
func TestCustomRuleSpecialFilesAreConfigErrors(t *testing.T) {
	dir := writeMarkerRule(t, filepath.Join(t.TempDir(), "rules"), "PACK_A_001", "pack-a-marker")
	fifo := filepath.Join(dir, "pipe.yaml")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	zero := filepath.Join(dir, "zero.yml")
	symlinkOrSkip(t, "/dev/zero", zero)

	done := make(chan error, 1)
	go func() {
		_, err := aguara.NewScanner(aguara.WithCustomRules(dir))
		done <- err
	}()
	var err error
	select {
	case err = <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("NewScanner blocked on a special rule file")
	}
	requireProblem(t, err, aguara.ConfigProblemInvalidRule, "", fifo)
	requireProblem(t, err, aguara.ConfigProblemInvalidRule, "", zero)

	sc, err := aguara.NewScanner(aguara.WithCustomRules(dir), aguara.WithLenientConfig())
	if err != nil {
		t.Fatal(err)
	}
	if catalogCount(sc.ListRules(), "PACK_A_001") != 1 || len(sc.ConfigProblems()) != 2 {
		t.Fatalf("lenient: problems %+v", sc.ConfigProblems())
	}
}
