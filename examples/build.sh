#!/bin/bash
set -e

# Get the script's directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Find all example directories containing main.go
echo "Building examples..."
for example_dir in "$SCRIPT_DIR"/*/; do
    if [[ -f "$example_dir/main.go" ]]; then
        example_name=$(basename "$example_dir")
        echo "Building $example_name..."
        go build -o "$example_dir$example_name" "$example_dir/main.go"
        echo "  ✓ Built: $example_dir$example_name"
    fi
done
