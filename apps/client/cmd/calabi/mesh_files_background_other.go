//go:build !windows

package main

import "context"

func runBackgroundFileAgent(_ bool, _ string) int { return 2 }

func connectFileConsole(_ context.Context, _ string) (bool, int) { return false, 0 }
