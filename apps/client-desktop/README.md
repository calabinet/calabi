# Calabi desktop app

A window and a tray icon for the `calabi` client, built with Tauri 2. The window
shows the client's local console (`http://127.0.0.1:7400`) — the same page a
browser shows. The app has no web code of its own.

Released for Windows (a setup `.exe`) and macOS (a `.pkg`).

## How it works

- **The installer installs the client as a system service.** The Windows setup
  ships `calabi.exe` beside the app (`bundle.resources` in
  `src-tauri/tauri.windows.conf.json`) and registers it with
  `calabi daemon install --system` (`src-tauri/nsis-hooks.nsh`). The macOS
  `.pkg` installs the app and the client as a LaunchDaemon. The service runs the
  tunnels and the mesh whether the app is open or not.
- **The app attaches to the service.** It finds the service's console and shows
  it in the window; the tray shows the service's state, checked every five
  seconds. A release build never starts a daemon of its own.
- **Updates come from the service.** Signed in to calabi.net, the service checks
  a signed manifest on `download.calabi.net` and installs new releases, as its
  update settings in the console allow. A daemon on a self-hosted server does not
  check. The app itself has no updater.
- The installers are not code-signed yet: Windows SmartScreen and macOS
  Gatekeeper warn on first open.

## Build

Needs Rust (stable), Go 1.25+ and the Tauri 2 CLI
(`cargo install tauri-cli --version "^2"`), plus:

- Windows: the MSVC build tools and the WebView2 runtime (included in Windows 11);
- macOS: the Xcode command-line tools;
- Linux: `webkit2gtk-4.1-dev`, `libssl-dev`, `libgtk-3-dev`, `librsvg2-dev`,
  `libayatana-appindicator3-dev`.

On Windows, put the client where the installer picks it up, then build:

```bash
( cd apps/client && go build -o ../client-desktop/src-tauri/binaries/calabi.exe ./cmd/calabi )
cd apps/client-desktop/src-tauri
cargo tauri build      # the installer is under target/release/bundle/nsis/
```

On macOS and Linux, `cargo tauri build` makes the app bundle. The released
macOS `.pkg` wraps the `.app` together with the client and its LaunchDaemon.

### Running it while developing

```bash
cd apps/client-desktop/src-tauri
cargo tauri dev
```

A debug build attaches to a running service, like a release build. When there
is none, it starts a daemon itself, looking for `calabi` in this order:

1. `CALABI_DAEMON_PATH` — set it for the current shell only
   (`$env:CALABI_DAEMON_PATH = "$PWD\bin\calabi.exe"`); release builds ignore it;
2. next to the app;
3. `PATH`.

Or start `calabi daemon` in another terminal first.

## Layout

```
apps/client-desktop/
├── shell/index.html           # shown until the console answers
├── tests/nsis-hooks/          # tests for the installer hooks (Windows)
└── src-tauri/
    ├── tauri.conf.json        # the app; tauri.windows.conf.json adds the installer settings
    ├── nsis-hooks.nsh         # Windows installer: register and remove the service
    ├── binaries/              # where the build expects calabi(.exe)
    ├── capabilities/          # what the window may do
    ├── icons/
    └── src/
        ├── main.rs            # window, tray, single instance, start at login
        └── daemon.rs          # finding and attaching to the service
```
