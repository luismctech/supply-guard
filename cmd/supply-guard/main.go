package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/AlbertoMZCruz/supply-guard/internal/cmd"
	"github.com/AlbertoMZCruz/supply-guard/internal/ui"
)

func main() {
	if err := cmd.Execute(); err != nil {
		if errors.Is(err, cmd.ErrFindingsExceedThreshold) {
			os.Exit(1)
		}
		var sevErr *cmd.SeverityExitError
		if errors.As(err, &sevErr) {
			os.Exit(sevErr.Code)
		}
		fmt.Fprintf(os.Stderr, "%s %v\n", ui.Error("Error:"), err)
		os.Exit(2)
	}
}
