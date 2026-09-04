//go:build windows && arm64

package mesh

import _ "embed"

// wintunDLL is the arm64 Wintun driver, extracted + pre-loaded by ensureWintun.
// Only this architecture's DLL is compiled into an arm64 build. See wintun/README.md.
//
//go:embed wintun/arm64/wintun.dll
var wintunDLL []byte
