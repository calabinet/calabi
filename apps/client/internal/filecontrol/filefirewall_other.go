//go:build !windows

package filecontrol

import "context"

func ReceptionFirewall() func(context.Context, bool) error {
	return nil
}
