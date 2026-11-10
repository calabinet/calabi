//go:build !windows

package assistance

import (
	"context"
	"errors"
)

func openWindow(context.Context, string) (window, error) {
	return nil, errors.New("Windows assistance host required")
}
