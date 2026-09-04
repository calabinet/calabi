Tauri requires platform-specific icon assets in this directory.

To regenerate (committed assets cover Windows + macOS + Linux):

    # Windows
    pwsh scripts\gen-desktop-icons.ps1
    # Linux / macOS
    ./scripts/gen-desktop-icons.sh

The generator builds a placeholder 1024×1024 PNG (blue rounded square +
white "C") then runs `cargo tauri icon` to fan it out to:

    32x32.png        128x128.png       128x128@2x.png
    icon.icns (mac)  icon.ico (win)
    Square*Logo.png  StoreLogo.png     and other macOS variants

CI gates the bundle step on these existing — if you're adding a new
platform, regenerate first. When marketing hands us a real designed
logo, drop the 1024×1024 PNG in this directory as source.png and re-run
the generator (it'll use the existing source instead of synthesising one).
