# Calabi for Android

The phone joins its org's meshnet as a device. All networking — sign-in, the
control plane, WireGuard — is the Go core in [`apps/client/mobile`](../client/mobile),
bound into this app with gomobile. The app draws the screens and owns the VPN
(`CalabiVpnService`).

It signs in to calabi.net (or a development control plane, below) and enrols
through it; it does not join a self-hosted `calabi-coord` yet.

## Build

Needs JDK 17, the Android SDK (platform 35, build-tools 35) with NDK r27, and
gomobile:

```bash
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/cmd/gobind@latest
```

1. Build the Go core into `app/libs/calabicore.aar`. It embeds the edge CA the
   client trusts. Without `-EdgeCa` that is whatever the tree carries (the
   development edge CA, `CN=calabi-dev-edge-ca`), and the app cannot reach
   calabi.net.
   calabi.net's edge-CA root is a public certificate carried in every release's
   `build-manifest.json`:

   ```bash
   jq -r '.inputs.edge_ca.pem[]' build-manifest.json > calabi-edge-ca.pem
   ```

   ```powershell
   scripts\mobile\build-core-android.ps1 -EdgeCa calabi-edge-ca.pem
   ```

2. Build the app (`local.properties` names the SDK, e.g. `sdk.dir=C\:\\Android\\Sdk`):

   ```powershell
   cd apps\client-android
   .\gradlew.bat assembleDebug
   ```

   The APK is `app/build/outputs/apk/debug/app-debug.apk`.

A development control plane: `-PcalabiBffUrl=http://192.0.2.10:8002
-PcalabiConsoleUrl=http://192.0.2.10:5173 -PcalabiCoordPlaintext=true`.

A signed release build: set `CALABI_ANDROID_KEYSTORE` (path to your `.jks`),
`CALABI_ANDROID_KEYSTORE_PASSWORD` and, if the alias is not `calabi`,
`CALABI_ANDROID_KEY_ALIAS`, then `.\gradlew.bat -PcalabiVersion=<version> assembleRelease`.
Without the keystore variables the release APK comes out unsigned. The official
APK is built by `scripts/mobile/build-release-android.ps1`, which runs from the
maintainers' tree (it reads the `VERSION` file this repository does not carry)
and checks that the APK is signed by the certificate in
`scripts/mobile/android-release-cert.sha256`.

## Layout

| File | What it does |
|---|---|
| `CalabiApp.kt` | Creates the Go core once per process |
| `AppPlatform.kt` | What the core asks of Android: establish the VPN, protect sockets, list networks, log |
| `CalabiVpnService.kt` | The VPN: foreground service, `establish()` on the core's request, network-change callbacks |
| `ConnectTileService.kt` | Quick Settings tile |
| `BootReceiver.kt` | Connect at startup |
| `BackgroundRun.kt` | Where each phone maker lets an app keep running in the background |
| `CoreClient.kt` | Calls the core's in-process `/v1/*` API |
| `ui/` | Sign-in, mesh, tunnels, settings (Jetpack Compose) |
