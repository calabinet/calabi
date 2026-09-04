# Bundled Wintun driver (Windows)

`wintun.dll` is the [Wintun](https://www.wintun.net/) TUN driver from the
WireGuard project. Calabi's mesh (Connect) data plane creates its WireGuard tun
interface via `golang.zx2c4.com/wireguard/tun`, which on Windows loads
`wintun.dll` at runtime. Bundling it here lets `calabi.exe` bring the mesh up on
Windows with no separate driver install — `ensureWintun` (see
`../wintun_windows.go`) extracts the arch-matched DLL and pre-loads it before the
tun is created.

## Provenance

- Source: <https://www.wintun.net/builds/wintun-0.14.1.zip>
- Version: **0.14.1**
- Archive SHA-256: `07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51`
- `amd64/wintun.dll` and `arm64/wintun.dll` are copied verbatim from `bin/{amd64,arm64}/`
  in that archive.
- Both are Authenticode-signed by `CN=WireGuard LLC` (verified `Valid` at import
  time). Each build embeds only its own architecture's DLL (per-arch `go:embed`),
  so a given `calabi.exe` carries exactly one.

## License

Wintun is distributed by WireGuard LLC. The prebuilt, signed `wintun.dll`
binaries published at wintun.net may be redistributed freely alongside
applications that use them; see the Wintun project for details. Do not modify the
binaries — a modified DLL loses its signature and Wintun refuses to load it.

## Updating

Download a newer `wintun-<version>.zip` from wintun.net, verify each DLL's
Authenticode signature is `Valid` and signed by WireGuard LLC, replace the files
here, and update the version + hash above.
