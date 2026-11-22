#!/bin/sh
# Build "Teleporter.app": the menu bar app with the CLI beside it,
# where "Install Helper…" expects to find it.
set -eu
cd "$(dirname "$0")/.."

bin=target/release
if [ "${1:-}" = --universal ]; then
    # One app for both Apple silicon and Intel Macs, as releases ship it.
    cargo build --release --workspace --locked --target aarch64-apple-darwin --target x86_64-apple-darwin
    bin=target/universal
    mkdir -p "$bin"
    for name in teleporter teleporter-menubar; do
        lipo -create -output "$bin/$name" \
            "target/aarch64-apple-darwin/release/$name" "target/x86_64-apple-darwin/release/$name"
    done
else
    cargo build --release --workspace
fi
version=$(cargo pkgid -p teleporter | sed 's/.*[#@]//')
app="target/Teleporter.app"

rm -rf "$app"
mkdir -p "$app/Contents/MacOS"
cp "$bin/teleporter" "$bin/teleporter-menubar" "$app/Contents/MacOS/"
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
# The CLI is a second executable in the bundle, so it is signed on its own first.
codesign --force --sign - "$app/Contents/MacOS/teleporter"
codesign --force --sign - "$app"
echo "Built $app"
