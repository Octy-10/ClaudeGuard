#!/bin/bash
set -euo pipefail

arch="${1:?Specify arm64 or x86_64}"
case "$arch" in arm64|x86_64) ;; *) exit 2 ;; esac
test "$(uname -m)" = "$arch"
cd "$(dirname "$0")/.."
app_id=io.github.octy-10.claudeguard
filter_id="$app_id.filter"
version="$(python -c 'from guard import __version__; print(__version__)')"
team="${MACOS_TEAM_ID:-ADHOCTEAM0}"
identity="${MACOS_APPLICATION_IDENTITY:--}"
native="$(mktemp -d)"
trap 'rm -rf "$native"' EXIT

if [[ "$identity" != '-' ]]; then
  [[ "$team" =~ ^[A-Z0-9]{10}$ ]]
  for profile in "${MACOS_APP_PROFILE:?}" "${MACOS_FILTER_PROFILE:?}"; do
    security cms -D -i "$profile" > "$native/$(basename "$profile").plist"
  done
fi

python -m PyInstaller --clean --noconfirm ClaudeGuard-macos.spec
app=dist/ClaudeGuard.app
content="$app/Contents"
extension="$content/Library/SystemExtensions/$filter_id.systemextension/Contents"
mkdir -p "$extension/MacOS" "$content/Library/LaunchAgents"
python macos/bundle_metadata.py "$content" "$extension" "$native" "$version" "$team" "$identity"

xcrun swiftc -swift-version 5 -target "$arch-apple-macos15.0" -o "$native/packet-policy-tests" \
  tests/packet-policy.swift macos/Filter/PacketPolicy.swift "$native/ProtectedAddresses.swift"
"$native/packet-policy-tests"
xcrun swiftc -swift-version 5 -O -target "$arch-apple-macos15.0" -emit-library \
  -o "$content/Frameworks/libClaudeGuardHost.dylib" macos/Host.swift
xcrun swiftc -swift-version 5 -O -target "$arch-apple-macos15.0" \
  -o "$extension/MacOS/ClaudeGuardFilter" macos/Filter/main.swift macos/Filter/PacketPolicy.swift "$native/ProtectedAddresses.swift"
xcrun swiftc -swift-version 5 -O -target "$arch-apple-macos15.0" \
  -o "$native/$app_id.settings" macos/Settings/main.swift

if [[ "$identity" == '-' ]]; then
  codesign --force --sign - "$content/Frameworks/libClaudeGuardHost.dylib"
  codesign --force --sign - "$(dirname "$extension")"
  codesign --force --sign - "$app"
else
  cp "$MACOS_APP_PROFILE" "$content/embedded.provisionprofile"
  cp "$MACOS_FILTER_PROFILE" "$extension/embedded.provisionprofile"
  codesign --force --timestamp --options runtime --sign "$identity" "$content/Frameworks/libClaudeGuardHost.dylib"
  codesign --force --timestamp --options runtime --sign "$identity" --entitlements "$native/filter.entitlements" "$(dirname "$extension")"
  codesign --force --timestamp --options runtime --sign "$identity" --entitlements "$native/app.entitlements" "$app"
  codesign --force --timestamp --options runtime --sign "$identity" "$native/$app_id.settings"
fi

codesign --verify --deep --strict "$app"
for executable in "$content/MacOS/ClaudeGuard" "$content/Frameworks/libClaudeGuardHost.dylib" \
  "$extension/MacOS/ClaudeGuardFilter" "$native/$app_id.settings"; do
  lipo -verify_arch "$arch" "$executable"
done
"$native/$app_id.settings" status | python -c 'import json, sys; status = json.load(sys.stdin); print(status); sys.exit(0 if status.get("ok") is True else 1)'

if [[ "$identity" == '-' ]]; then
  ditto -c -k --sequesterRsrc --keepParent "$app" "dist/ClaudeGuard-macOS-$arch.zip"
  exit 0
fi

stage="$native/payload"
mkdir -p "$stage/Applications" "$stage/Library/PrivilegedHelperTools"
ditto "$app" "$stage/Applications/ClaudeGuard.app"
install -m 0755 "$native/$app_id.settings" "$stage/Library/PrivilegedHelperTools/$app_id.settings"
pkgbuild --analyze --root "$stage" "$native/components.plist"
python - "$native/components.plist" <<'PY'
import plistlib
import sys
from pathlib import Path
path = Path(sys.argv[1])
data = plistlib.loads(path.read_bytes())
for bundle in data:
    bundle['BundleIsRelocatable'] = False
    bundle['BundleHasStrictIdentifier'] = True
    bundle['BundleOverwriteAction'] = 'upgrade'
path.write_bytes(plistlib.dumps(data))
PY

pkg="dist/ClaudeGuard-macOS-$arch.pkg"
pkgbuild --root "$stage" --install-location / --ownership recommended --component-plist "$native/components.plist" \
  --identifier "$app_id.pkg" --version "$version" --sign "${MACOS_INSTALLER_IDENTITY:?}" "$pkg"

xcrun notarytool submit "$pkg" --key "${MACOS_NOTARY_KEY:?}" \
  --key-id "${MACOS_NOTARY_KEY_ID:?}" --issuer "${MACOS_NOTARY_ISSUER_ID:?}" --wait --timeout 25m
xcrun stapler staple "$pkg"
xcrun stapler validate "$pkg"
pkgutil --check-signature "$pkg"
spctl --assess --type install --verbose=2 "$pkg"
