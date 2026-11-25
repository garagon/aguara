package commands

import (
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/garagon/aguara/internal/safefile"
)

// writeReport renders a report to stdout, or to the -o file when one is
// set. Every format goes through here, so -o never silently falls back
// to stdout for one of them.
func writeReport(render func(io.Writer) error) error {
	if flagOutput == "" {
		return render(os.Stdout)
	}
	return safefile.Write(flagOutput, render)
}

// writeCommandReport is writeReport for commands that print through
// cobra's configured output writer when no -o file is set.
func writeCommandReport(cmd *cobra.Command, render func(io.Writer) error) error {
	if flagOutput == "" {
		return render(cmd.OutOrStdout())
	}
	return safefile.Write(flagOutput, render)
}
