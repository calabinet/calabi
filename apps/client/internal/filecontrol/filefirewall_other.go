//go:build !windows

package filecontrol

import (
	"context"
	"errors"
)

func ReceptionFirewall() func(context.Context, bool) error {
	return nil
}

func InstallationFirewall(context.Context, bool) error {
	return errors.New("file firewall installation is only supported on Windows")
}
