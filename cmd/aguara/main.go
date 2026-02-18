package main

import (
	"os"

	"github.com/garagon/aguara/cmd/aguara/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		os.Exit(2)
	}
}
