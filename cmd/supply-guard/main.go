package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/AlbertoMZCruz/supply-guard/internal/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		if errors.Is(err, cmd.ErrFindingsExceedThreshold) {
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}
}
