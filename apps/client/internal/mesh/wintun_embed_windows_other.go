//go:build windows && !amd64 && !arm64

package mesh

// wintunDLL is empty on Windows architectures we don't bundle a driver for (only
// amd64 + arm64 ship one). ensureWintun then no-ops and tun creation falls back to
// a system-installed wintun.dll (exe dir or System32).
var wintunDLL []byte
