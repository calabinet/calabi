# Calabi for Android

The phone joins its org's meshnet as a device. All networking — sign-in, the
control plane, WireGuard — is the Go core in [`apps/client/mobile`](../client/mobile),
bound into this app with gomobile. The app draws the screens and owns the VPN
(`CalabiVpnService`). Design: [docs/runbook/mobile-client-plan.md](../../docs/runbook/mobile-client-plan.md).

## Build

Needs JDK 17, the Android SDK (platform 35, build-tools 35) with NDK r27, and
gomobile:

```bash
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/cmd/gobind@latest
```

1. Build the Go core into `app/libs/calabicore.aar`. Without `-EdgeCa` it embeds
   the DEV edge CA and can only reach a development control plane; for the
   production one pass the deployment's public CA:

   ```powershell
   scripts\mobile\build-core-android.ps1 -EdgeCa deploy\compose\data\edge-certs\ca.crt
   ```

2. Build the app (`local.properties` names the SDK: `sdk.dir=D\:\\Android\\Sdk`):

   ```powershell
   cd apps\client-android
   .\gradlew.bat assembleDebug
   ```

   The APK is `app/build/outputs/apk/debug/app-debug.apk`.

A development control plane: `-PcalabiBffUrl=http://192.0.2.10:8002
-PcalabiConsoleUrl=http://192.0.2.10:5173 -PcalabiCoordPlaintext=true`.

## Layout

| File | What it does |
|---|---|
| `CalabiApp.kt` | Creates the Go core once per process |
| `AppPlatform.kt` | What the core asks of Android: establish the VPN, protect sockets, list networks, log |
| `CalabiVpnService.kt` | The VPN: foreground service, `establish()` on the core's request, network-change callbacks |
| `ConnectTileService.kt` | Quick Settings tile |
| `CoreClient.kt` | Calls the core's in-process `/v1/*` API |
| `ui/` | Sign-in, devices, settings (Jetpack Compose) |
