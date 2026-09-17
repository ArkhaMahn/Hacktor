#!/usr/bin/env bash
# Build script for the "Hacktor" ZAP addon.
# Compiles against ZAP 2.17.0 and packages as a .zap file.
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZAP_JAR="/opt/ZAP_2.17.0/zap-2.17.0.jar"
RSYNTAX_JAR="/opt/ZAP_2.17.0/lib/rsyntaxtextarea-3.6.0.jar"
SRC_DIR="$BASE_DIR/src/main/java"
RES_DIR="$BASE_DIR/src/main/resources"
OUT_DIR="$BASE_DIR/build"
CLS_DIR="$OUT_DIR/classes"
ADDON_DIR="$OUT_DIR/addon"
DIST_DIR="$OUT_DIR/dist"
VERSION="1.0.0"
ADDON_FILE="$DIST_DIR/hacktor-alpha-${VERSION}.zap"

echo "==> Compiling addon against $ZAP_JAR"
rm -rf "$CLS_DIR" "$ADDON_DIR" "$DIST_DIR"
mkdir -p "$CLS_DIR" "$ADDON_DIR" "$DIST_DIR"

find "$SRC_DIR" -name '*.java' > "$OUT_DIR/sources.txt"

javac --release 17 -encoding UTF-8 \
  -classpath "$ZAP_JAR:$RSYNTAX_JAR" \
  -d "$CLS_DIR" \
  @"$OUT_DIR/sources.txt"

echo "==> Assembling unpacked addon directory at $ADDON_DIR"
cp -r "$CLS_DIR"/. "$ADDON_DIR/"
cp -r "$RES_DIR"/. "$ADDON_DIR/"
cp "$BASE_DIR/ZapAddOn.xml" "$ADDON_DIR/ZapAddOn.xml"

echo "==> Packaging $ADDON_FILE"
( cd "$ADDON_DIR" && zip -qr "$ADDON_FILE" . )

echo "==> Done."
echo "    Unpacked addon: $ADDON_DIR"
echo "    Packaged addon: $ADDON_FILE"
echo
echo "Install:"
echo "  ZAP GUI -> Manage Add-ons -> Install local add-on (.zap file)"
