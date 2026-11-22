#!/bin/sh
# Build "Teleporter.app": the menu bar app with the CLI beside it,
# where "Install Helper…" expects to find it.
set -eu
cd "$(dirname "$0")/.."

cargo build --release --workspace
version=$(cargo pkgid -p teleporter | sed 's/.*[#@]//')
app="target/Teleporter.app"

rm -rf "$app"
mkdir -p "$app/Contents/MacOS"
cp target/release/teleporter target/release/teleporter-menubar "$app/Contents/MacOS/"
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>teleporter-menubar</string>
    <key>CFBundleIdentifier</key>
    <string>io.github.balcsida.teleporter</string>
    <key>CFBundleName</key>
    <string>Teleporter</string>
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
