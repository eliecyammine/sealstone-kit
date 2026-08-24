#!/bin/sh
# Refresh the vector corpus from sealstone-format.
#
# The corpus is committed here so this package tests standalone, but
# sealstone-format owns it. Run this after the corpus changes there.
set -e
SOURCE="${1:-../sealstone-format/vectors}"
DEST="$(dirname "$0")/../Tests/ConformanceTests/Vectors"

if [ ! -d "$SOURCE" ]; then
  echo "Cannot find the corpus at $SOURCE"
  echo "Pass its path: Scripts/sync-vectors.sh /path/to/sealstone-format/vectors"
  exit 1
fi

rm -rf "$DEST"
mkdir -p "$DEST"
cp "$SOURCE/manifest.json" "$DEST/"
for dir in "$SOURCE"/[0-9][0-9]-*; do
  [ -d "$dir" ] && cp -R "$dir" "$DEST/"
done

echo "Synced $(find "$DEST" -type f | wc -l | tr -d ' ') files from $SOURCE"
