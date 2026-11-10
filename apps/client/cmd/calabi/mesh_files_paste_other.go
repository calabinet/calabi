//go:build !windows && !darwin

package main

import (
	"errors"
	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
)

func (d *desktopFileAgent) startShellPaste() {}
func (d *desktopFileAgent) rdpCopyAction(w *filetransfer.Workspace, a fileAction) (any, error) {
	return nil, errors.New("Windows clipboard bridge required")
}
