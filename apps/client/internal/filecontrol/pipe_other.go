//go:build !windows && !linux && !darwin

package filecontrol

import (
	"context"
	"errors"
)

func Serve(context.Context, *Control, string) (<-chan error, error) {
	return nil, errors.New("OS-user file agent IPC is not available on this platform yet")
}
func Call(context.Context, string, Request) (Snapshot, error) {
	return Snapshot{}, errors.New("OS-user file agent IPC is not available on this platform yet")
}
