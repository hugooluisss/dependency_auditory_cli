package main

import (
	"os"

	"github.com/hugooluisss/dependency_auditory_cli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
