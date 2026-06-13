// The gbrl-wasm command is a utility for running WASI-compatible binaries
// within the gbrl sandbox. It uses the internal SyscallInterceptor to
// monitor and control guest behavior, serving as a reference for the
// platform's sandboxing capabilities.
//
// Example usage:
//
//	gbrl-wasm [--sandbox <dir>] <file.wasm> [args...]
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/local/gbrl/internal/executor"
	"github.com/local/gbrl/internal/interceptor"
)

func main() {
	sandboxDir := flag.String("sandbox", "", "sandbox root directory (optional)")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: gbrl-wasm [--sandbox <dir>] <file.wasm> [args...]\n")
		os.Exit(1)
	}

	wasmBytes, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading %q: %v\n", args[0], err)
		os.Exit(1)
	}

	intercept := interceptor.AllowAllInterceptor{}

	exe := executor.New()
	ctx := context.Background()

	err = exe.Load(ctx, executor.GuestConfig{
		WASMBytes:   wasmBytes,
		Args:        args,
		SandboxRoot: *sandboxDir,
		Interceptor: intercept,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading: %v\n", err)
		os.Exit(1)
	}
	defer exe.Terminate(0)

	fmt.Fprintf(os.Stderr, "[gbrl] guest PID=%d running...\n", exe.PID())

	start := time.Now()
	exitCode, err := exe.Run(ctx)
	elapsed := time.Since(start)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gbrl] error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "[gbrl] guest exited code=%d in %v\n", exitCode, elapsed)
	os.Exit(int(exitCode))
}
