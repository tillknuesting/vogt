#!/bin/sh
# Builds "Vogt Helper.app" with swiftc and Apple frameworks only.
# Signs ad hoc unless SIGN_IDENTITY names a Developer ID certificate, in
# which case it signs with the hardened runtime for notarization.
set -eu
cd "$(dirname "$0")"
out=${OUT:-build}
app="$out/Vogt Helper.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS"
swiftc -O -swift-version 5 -target arm64-apple-macos26.0 \
	-framework AppKit -framework CryptoKit -framework LocalAuthentication -framework Security \
	-o "$app/Contents/MacOS/VogtHelper" VogtHelper.swift
cp Info.plist "$app/Contents/Info.plist"
if [ -n "${SIGN_IDENTITY:-}" ]; then
	codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$app"
else
	codesign --force --sign - "$app"
fi
codesign --verify --strict "$app"
echo "built $app"
