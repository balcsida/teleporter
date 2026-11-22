#!/bin/sh
# Build "Teleport Split Tunnel.app": the menu bar app with the CLI beside it,
# where "Install Helper…" expects to find it.
set -eu
cd "$(dirname "$0")/.."

cargo build --release --workspace
version=$(cargo pkgid -p teleport-split | sed 's/.*[#@]//')
app="target/Teleport Split Tunnel.app"

rm -rf "$app"
mkdir -p "$app/Contents/MacOS"
cp target/release/teleport-split target/release/teleport-split-menubar "$app/Contents/MacOS/"
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>teleport-split-menubar</string>
    <key>CFBundleIdentifier</key>
    <string>com.teleport-split-tunnel.app</string>
    <key>CFBundleName</key>
    <string>Teleport Split Tunnel</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>$version</string>
    <key>CFBundleURLTypes</key>
    <array>
        <dict>
            <key>CFBundleURLName</key>
            <string>UI account sign-in</string>
            <key>CFBundleURLSchemes</key>
            <array>
                <string>wifiman-desktop-dl</string>
            </array>
        </dict>
    </array>
    <key>LSUIElement</key>
    <true/>
</dict>
</plist>
PLIST
# Ad-hoc: enough to run locally. Distribution needs a Developer ID and notarization.
codesign --force --sign - "$app"
echo "Built $app"
