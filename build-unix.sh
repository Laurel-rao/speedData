#!/bin/sh
set -eu

cd "$(dirname "$0")"
mkdir -p dist
for target_os in darwin linux; do
    for target_arch in arm64 amd64; do
        output="dist/filetransfer-${target_os}-${target_arch}"
        printf 'Building %s\n' "$output"
        CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" \
            go build -trimpath -ldflags '-s -w' -o "$output" .
        chmod +x "$output"
    done
done
