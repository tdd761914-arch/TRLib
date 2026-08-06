#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
base_target="$repo_dir/target/size-base"
crypto_target="$repo_dir/target/size-crypto"
compat_target="$repo_dir/target/size-compat"

CARGO_TARGET_DIR="$base_target" cargo build \
  --manifest-path "$repo_dir/Cargo.toml" --locked --release \
  --package size-probe --no-default-features --features transport-intermediate

CARGO_TARGET_DIR="$crypto_target" cargo build \
  --manifest-path "$repo_dir/Cargo.toml" --locked --release \
  --package size-probe --no-default-features \
  --features transport-intermediate,crypto-rustcrypto

CARGO_TARGET_DIR="$compat_target" cargo build \
  --manifest-path "$repo_dir/Cargo.toml" --locked --release \
  --package size-probe --no-default-features \
  --features transport-intermediate,tdlib-compat

stat -c '%n %s bytes' \
  "$base_target/release/size-probe" \
  "$crypto_target/release/size-probe" \
  "$compat_target/release/size-probe"

size \
  "$base_target/release/size-probe" \
  "$crypto_target/release/size-probe" \
  "$compat_target/release/size-probe"
