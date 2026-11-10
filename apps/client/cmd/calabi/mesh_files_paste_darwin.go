package main

import (
	"errors"
	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
)

// AppKit lives in the authenticated RDP child; private desktop IPC carries its
// clipboard requests. The user agent owns TLS and the session lease, not AppKit.
func (d *desktopFileAgent) startShellPaste() { d.shellPasteLive.Store(true) }
func (d *desktopFileAgent) rdpCopyAction(w *filetransfer.Workspace, a fileAction) (any, error) {
	return nil, errors.New("legacy Windows clipboard bridge unavailable")
}
