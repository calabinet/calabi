// scaffold for the writable client UI.
//
// deliverable (this file):
//   - go:embed the static SPA shipped under./ui/dist
//   - expose UIFileSystem() so can mount it on the status server
//   - keep an explicit "do not import this status.go"
//     boundary so the placeholder HTML doesn't accidentally take over
//     the existing read-only status page
//
// replaces the placeholder
// index.html with the built Vite + React SPA and wires:
//
//   mux.Handle("/ui/", http.StripPrefix("/ui/", http.FileServer(http.FS(UIFileSystem()))))
//
// onto Server.Run. The writable REST endpoints (POST /api/tunnels,
// DELETE /api/tunnels/:id) live in a new internal/status/api package
// added; only locks the embedding mechanism.
//
// CLI binary size note: the placeholder index.html is < 1 KB, so the
// CLI grows by < 1 KB. real SPA targets ≤ 5 MB
// gzipped per the acceptance check.
//

package status

import (
	"embed"
	"io/fs"
)

//go:embed all:ui/dist
var uiDistFS embed.FS

// UIFileSystem returns the embedded SPA root as an fs.FS. The root
// is the contents of ui/dist (the prefix is stripped).
//
// Returns an error path only when the embed itself is broken — that
// should be caught at compile time, but the function returns an error
// so callers don't have to panic at boot.
func UIFileSystem() (fs.FS, error) {
	return fs.Sub(uiDistFS, "ui/dist")
}
