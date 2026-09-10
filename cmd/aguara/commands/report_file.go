package commands

import (
	"io"
	"os"

	"github.com/garagon/aguara/internal/safefile"
)

func writeReport(render func(io.Writer) error) error {
	if flagOutput == "" {
		return render(os.Stdout)
	}
	return safefile.Write(flagOutput, render)
}
