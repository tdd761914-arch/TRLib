#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
generated=$(mktemp "${TMPDIR:-/tmp}/trlib-generated.XXXXXX")
trap 'rm -f "$generated"' EXIT HUP INT TERM

cargo run --quiet --manifest-path "$repo_dir/Cargo.toml" \
  --package tl-prefix-gen -- --output "$generated" \
  "$repo_dir/schemas/core.tl" "$repo_dir/schemas/tg_api_subset.tl"
diff -u "$repo_dir/crates/trlib-core/src/generated.rs" "$generated"
