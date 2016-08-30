package main

import (
	"os"

	"github.com/jessevdk/go-flags"
	"github.com/pivotal-cf/scantron/commands"
)

func main() {
	parser := flags.NewParser(&commands.Scantron, flags.Default)

	_, err := parser.Parse()
	if err != nil {
		os.Exit(1)
	}
}
