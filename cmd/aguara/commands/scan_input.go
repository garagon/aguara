package commands

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/garagon/aguara/internal/output"
	"github.com/garagon/aguara/internal/scanner"
)

var flagScanRoot string

// scanInput is what a scan command line asked to read: one path (the
// behaviour of every earlier release) or several paths under one scan
// root.
type scanInput struct {
	args []string
	root string // scan root for a path list; "" for a single path
}

func parseScanInput(_ *cobra.Command, args []string) (scanInput, error) {
	in := scanInput{args: args}
	if len(args) == 1 && flagScanRoot == "" {
		return in, nil
	}
	if flagChanged {
		return in, errors.New("--changed scans the changes under one path; pass a single path, or drop --changed to scan these paths")
	}
	in.root = flagScanRoot
	if in.root == "" {
		in.root = "."
	}
	info, err := os.Stat(in.root)
	if err != nil {
		return in, fmt.Errorf("--root: %w", err)
	}
	if !info.IsDir() {
		return in, fmt.Errorf("--root: %s is not a directory", in.root)
	}
	return in, nil
}

// policyPath is where project policy files are read: the scan root of a
// path list, or the single path.
func (in scanInput) policyPath() string {
	if in.root != "" {
		return in.root
	}
	if len(in.args) == 0 {
		return ""
	}
	return in.args[0]
}

// target is the Target line of the report.
func (in scanInput) target() string {
	if in.root != "" && len(in.args) > 1 {
		return fmt.Sprintf("%d paths under %s", len(in.args), in.root)
	}
	return in.args[0]
}

func (in scanInput) execute(ctx context.Context, s *scanner.Scanner) (*scanner.ScanResult, error) {
	if in.root != "" {
		result, links, err := s.ScanPaths(ctx, in.root, in.args)
		if err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}
		for _, link := range links {
			fmt.Fprintf(os.Stderr, "notice: %s is a symbolic link and was not scanned (directory walks skip links too)\n", output.TerminalText(link))
		}
		return result, nil
	}
	return executeScan(ctx, s, in.args[0])
}
