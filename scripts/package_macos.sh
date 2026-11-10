#!/bin/bash
# Bundle the p2p binary with its Homebrew dylib dependencies into a
# self-contained folder that runs on machines without the dev libraries.
#
# Usage: ./scripts/package_macos.sh [path/to/p2p] [output-dir]
set -euo pipefail

BIN="${1:-build/p2p}"
OUT="${2:-dist/p2p-macos-$(uname -m)}"

rm -rf "$OUT"
mkdir -p "$OUT"
cp "$BIN" "$OUT/p2p"
chmod +x "$OUT/p2p"

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
    cp "$lib" "$OUT/$ref_name"
    chmod u+w "$OUT/$ref_name"
    while IFS= read -r dep; do
        cdep="$(canon "$dep")"
        grep -qxF "$cdep" "$SEEN" || queue+=("$cdep|$(basename "$dep")")
    done < <(non_system_dylibs "$lib")
done

# Rewrite absolute install names to @rpath/<bundled name>. @rpath references
# between bundled libs already work via @executable_path.
while IFS= read -r f; do
    base="$(basename "$f")"
    install_name_tool -id "@rpath/$base" "$f" 2>/dev/null || true
    install_name_tool -add_rpath @executable_path "$f" 2>/dev/null || true
    non_system_dylibs "$f" | while IFS= read -r old; do
        bundled="$(map_lookup "$(canon "$old")")"
        bundled="${bundled:-$(basename "$old")}"
        install_name_tool -change "$old" "@rpath/$bundled" "$f"
    done
done < <(find "$OUT" -type f)

# install_name_tool invalidated the signatures; arm64 macOS refuses to load
# dylibs with invalid signatures, so re-sign everything ad-hoc.
find "$OUT" -type f | while IFS= read -r f; do
    codesign --force --sign - "$f" 2>/dev/null || true
done

echo "Packaged: $OUT"
ls -la "$OUT"
