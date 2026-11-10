#!/bin/bash
# Bundle the p2p binary as a self-contained p2p.app: the executable plus
# its Homebrew dylib dependencies and an Info.plist describing the app
# to macOS (name, version, bundle id). Ad-hoc signed — enough for local
# use; Gatekeeper still warns until a Developer ID signature + notarization
# is added.
#
# Usage: ./scripts/package_macos.sh [path/to/p2p] [output-dir] [version]
set -euo pipefail

BIN="${1:-build/p2p}"
OUT="${2:-dist/p2p-macos-$(uname -m)}"
VERSION="${3:-0.0.0}"

APP="$OUT/p2p.app"
RES="$APP/Contents/Resources"
MACOS_DIR="$APP/Contents/MacOS"

rm -rf "$OUT"
mkdir -p "$RES" "$MACOS_DIR"
cp "$BIN" "$MACOS_DIR/p2p"
chmod +x "$MACOS_DIR/p2p"

cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>p2p</string>
    <key>CFBundleIdentifier</key>
    <string>com.github.immersedin.enb</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>p2p</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>$VERSION</string>
    <key>CFBundleVersion</key>
    <string>$VERSION</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
EOF

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
SEEN="$WORK/seen"   # canonical paths already bundled
MAP="$WORK/map"     # canonical path -> bundled file name
: > "$SEEN"; : > "$MAP"

canon() {
    realpath "$1" 2>/dev/null || echo "$1"
}

map_lookup() {
    awk -F'\t' -v k="$1" '$1 == k {print $2; exit}' "$MAP"
}

non_system_dylibs() {
    otool -L "$1" | awk '$1 ~ /^\// && $1 !~ /^\/usr\/lib|^\/System/ {print $1}'
}

# Collect transitive non-system dylib dependencies. Dedup by canonical path
# (/opt/homebrew/opt and /opt/homebrew/Cellar may name the same file) but
# keep the file name the dependents actually reference.
queue=()
while IFS= read -r lib; do queue+=("$(canon "$lib")|$(basename "$lib")"); done < <(non_system_dylibs "$BIN")

while ((${#queue[@]})); do
    entry="${queue[0]}"
    queue=("${queue[@]:1}")
    lib="${entry%%|*}"
    ref_name="${entry##*|}"
    grep -qxF "$lib" "$SEEN" && continue
    echo "$lib" >> "$SEEN"
    printf '%s\t%s\n' "$lib" "$ref_name" >> "$MAP"
    [[ -f "$lib" ]] || continue
    cp "$lib" "$RES/$ref_name"
    chmod u+w "$RES/$ref_name"
    while IFS= read -r dep; do
        cdep="$(canon "$dep")"
        grep -qxF "$cdep" "$SEEN" || queue+=("$cdep|$(basename "$dep")")
    done < <(non_system_dylibs "$lib")
done

# Rewrite absolute install names to @rpath/<bundled name>. All files get
# @executable_path/../Resources as rpath — @executable_path always resolves
# relative to the main binary, so it works for the executable itself and
# for dylib-to-dylib references inside Resources/.
RPATH="@executable_path/../Resources"
while IFS= read -r f; do
    base="$(basename "$f")"
    install_name_tool -id "@rpath/$base" "$f" 2>/dev/null || true
    install_name_tool -add_rpath "$RPATH" "$f" 2>/dev/null || true
    non_system_dylibs "$f" | while IFS= read -r old; do
        bundled="$(map_lookup "$(canon "$old")")"
        bundled="${bundled:-$(basename "$old")}"
        install_name_tool -change "$old" "@rpath/$bundled" "$f"
    done
done < <(find "$RES" "$MACOS_DIR" -type f)

# Sign innermost first: dylibs, then the main executable, then the bundle.
find "$RES" -type f | while IFS= read -r f; do
    codesign --force --sign - "$f" 2>/dev/null || true
done
codesign --force --sign - "$MACOS_DIR/p2p" 2>/dev/null || true
codesign --force --sign - "$APP" 2>/dev/null || true

echo "Packaged: $APP"
find "$APP" -type f | sort
