//go:build windows && amd64

package mesh

import _ "embed"

// wintunDLL is the amd64 Wintun driver, extracted + pre-loaded by ensureWintun.
// Only this architecture's DLL is compiled into an amd64 build. See wintun/README.md.
//
//go:embed wintun/amd64/wintun.dll
var wintunDLL []byte
