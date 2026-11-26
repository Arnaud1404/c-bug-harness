#!/usr/bin/env bash
# Downloads CASTLE at a fixed commit into data/castle and the model files of
# models.lock into $MODELS_DIR, checking each model's SHA-256.
# Usage: scripts/fetch.sh
set -eu

cd "$(dirname "$0")/.."
castle_commit=c7391c9ec5dd944653103fbf55e7ebbf85842d82
models="${MODELS_DIR:-$HOME/llm/models}"

if [ ! -d data/castle ]; then
    git clone -q https://github.com/CASTLE-Benchmark/CASTLE-Benchmark data/castle
fi
git -C data/castle checkout -q "$castle_commit"

mkdir -p "$models"
grep -v '^#' models.lock | while read -r name url sha; do
    file="$models/$(basename "$url")"
    if [ ! -f "$file" ]; then
        echo "downloading $name"
        curl -fsSL -o "$file.part" "$url"
        mv "$file.part" "$file"
    fi
    echo "$sha  $file" | sha256sum -c --quiet - || { echo "bad checksum: $file" >&2; exit 1; }
done
echo "CASTLE at $castle_commit, models in $models"
