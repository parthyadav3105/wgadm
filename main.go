package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/parthyadav3105/wgadm/pkg/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	context.AfterFunc(ctx, stop) // calls stop() when ctx is cancelled

	os.Exit(cli.Run(ctx))
}
