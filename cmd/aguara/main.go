// Aguara CLI entry point.
package main

import (
	"errors"
	"os"

	"github.com/garagon/aguara/cmd/aguara/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		if errors.Is(err, commands.ErrThresholdExceeded) {
			os.Exit(1)
		}
		os.Exit(2)
	}
}
