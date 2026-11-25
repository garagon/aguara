package commands

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/garagon/aguara/internal/config"
	"github.com/garagon/aguara/internal/output"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

var (
	flagStdinFilename string
	flagScanRoot      string
)

// defaultStdinFilename matches the Go API, whose ScanContent treats
// content without a name as a skill.
const defaultStdinFilename = "skill.md"

// stdinPaths are the path arguments that mean "read standard input".
// /dev/stdin and its aliases are read the same way as "-" instead of being
// opened as a device file, which used to scan zero bytes.
var stdinPaths = map[string]bool{"-": true, "/dev/stdin": true, "/dev/fd/0": true, "/proc/self/fd/0": true}

// scanInput is what a scan command line asked to read: one path (the
// behaviour of every earlier release), several paths under one scan root,
// or standard input.
type scanInput struct {
	args      []string
	stdin     bool
	stdinName string
	reader    io.Reader
	root      string // scan root for a path list; "" for a single path
}

// stdinIsTerminal reports whether r is an interactive terminal, where a
// read would wait for typing instead of piped content. Tests replace it.
var stdinIsTerminal = func(r io.Reader) bool {
	f, ok := r.(*os.File)
	return ok && output.IsTerminal(f)
}

func parseScanInput(cmd *cobra.Command, args []string) (scanInput, error) {
	in := scanInput{args: args}
	stdinArgs := 0
	for _, a := range args {
		if stdinPaths[a] {
			stdinArgs++
		}
	}
	if stdinArgs > 0 {
		if len(args) > 1 {
			return in, errors.New("standard input (-) cannot be combined with other paths; scan it in its own run")
		}
		switch {
		case flagChanged:
			return in, errors.New("--changed lists files in a git work tree and cannot be combined with standard input (-)")
		case flagScanRoot != "":
			return in, errors.New("--root applies to path arguments, not to standard input (-)")
		case strings.EqualFold(strings.TrimSpace(flagProjectPolicy), "trust"):
			return in, errors.New("--project-policy trust does not apply to standard input (-): piped content has no project, " +
				"so no .aguara.yml or .aguaraignore is read and its inline aguara-ignore directives are never honored")
		}
		name, err := cleanStdinFilename(flagStdinFilename)
		if err != nil {
			return in, err
		}
		in.stdin, in.stdinName, in.reader = true, name, cmd.InOrStdin()
		if stdinIsTerminal(in.reader) {
			return in, errors.New("standard input is a terminal, so there is nothing to scan; pipe content in, for example:\n" +
				"  cat SKILL.md | aguara scan - --stdin-filename SKILL.md")
		}
		return in, nil
	}
	if cmd.Flags().Changed("stdin-filename") {
		return in, errors.New("--stdin-filename applies only when the path is - (standard input)")
	}
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

// cleanStdinFilename validates the name standard input is analyzed as.
func cleanStdinFilename(name string) (string, error) {
	if strings.TrimSpace(name) == "" || strings.ContainsAny(name, "\x00\r\n") {
		return "", errors.New("--stdin-filename must be a file name such as SKILL.md, mcp.json or .github/workflows/ci.yml")
	}
	clean := path.Clean(filepath.ToSlash(name))
	if base := path.Base(clean); base == "." || base == ".." || base == "/" || strings.HasSuffix(filepath.ToSlash(name), "/") {
		return "", fmt.Errorf("--stdin-filename %q names a directory; give a file name such as SKILL.md", name)
	}
	return clean, nil
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
	switch {
	case in.stdin:
		return "standard input as " + in.stdinName
	case in.root != "" && len(in.args) > 1:
		return fmt.Sprintf("%d paths under %s", len(in.args), in.root)
	}
	return in.args[0]
}

func (in scanInput) execute(ctx context.Context, s *scanner.Scanner, cfg config.Config) (*scanner.ScanResult, error) {
	switch {
	case in.stdin:
		return in.scanStdin(ctx, s, cfg)
	case in.root != "":
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

// scanStdin reads standard input up to the file-size limit and scans it as
// one file named in.stdinName. Empty input is a scan of zero files.
func (in scanInput) scanStdin(ctx context.Context, s *scanner.Scanner, cfg config.Config) (*scanner.ScanResult, error) {
	limit, err := parseMaxFileSize(cfg)
	if err != nil || limit <= 0 {
		limit = scanner.DefaultMaxFileSize // buildScanner already warned about an invalid value
	}
	data, err := readStdin(in.reader, limit)
	if err != nil {
		return nil, err
	}
	var targets []*scanner.Target
	if len(data) > 0 {
		targets = append(targets, &scanner.Target{RelPath: in.stdinName, Content: data})
	}
	result, err := s.ScanTargets(ctx, targets)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}
	return result, nil
}

// readStdin reads r to EOF, failing once it holds more than limit bytes.
// It reads one byte past the limit to tell a complete input from a
// truncated one, as the file reader does.
func readStdin(r io.Reader, limit int64) ([]byte, error) {
	readLimit := limit
	if readLimit < math.MaxInt64 {
		readLimit++
	}
	data, err := io.ReadAll(io.LimitReader(r, readLimit))
	if err != nil {
		return nil, fmt.Errorf("reading standard input: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("standard input is larger than the %d-byte limit; raise it with --max-file-size", limit)
	}
	return data, nil
}

// coverageScope adjusts the coverage scope for standard input.
func (in scanInput) coverageScope(cov *types.ScanCoverage) {
	if in.stdin && cov != nil {
		cov.Scope = types.ScanScopeStdin
	}
}
