package main

import (
	"fmt"
	"os"

	"secret-service/cmd/cli/commands"
)

func main() {
	if err := commands.NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
