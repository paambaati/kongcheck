// Command kongcheck detects Kong Konnect route collisions and shadowing.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/paambaati/kongcheck/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.NewApp().Run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
