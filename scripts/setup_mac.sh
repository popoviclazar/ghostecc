#!/bin/bash
set -euo pipefail
if [ "$(uname -s)" != "Darwin" ]; then
  echo 'Ovaj korak zahtijeva Mac sa Xcode-om.' >&2
  exit 1
fi
project_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$project_root"
for dependency in git xcodebuild rustup cargo pod cmake protoc; do
  if ! command -v "$dependency" >/dev/null 2>&1; then
    echo "Nedostaje: $dependency. Pogledaj docs/BUILDING.md." >&2
    exit 1
  fi
done
signal_commit='4beb029d8a941f81e7d9c6d8af1ed25a677569a8'
mkdir -p vendor
if [ ! -d vendor/libsignal/.git ]; then
  git clone https://github.com/signalapp/libsignal.git vendor/libsignal
fi
if [ -n "$(git -C vendor/libsignal status --porcelain)" ]; then
  echo 'vendor/libsignal ima lokalne promjene; sačuvaj ih prije ponovnog pokretanja.' >&2
  exit 1
fi
git -C vendor/libsignal fetch origin "$signal_commit"
git -C vendor/libsignal checkout --detach "$signal_commit"
test "$(git -C vendor/libsignal rev-parse HEAD)" = "$signal_commit"
(
  cd vendor/libsignal
  rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
  CARGO_BUILD_TARGET=aarch64-apple-ios swift/build_ffi.sh --release
  CARGO_BUILD_TARGET=aarch64-apple-ios-sim swift/build_ffi.sh --release
  CARGO_BUILD_TARGET=x86_64-apple-ios swift/build_ffi.sh --release
)
pod install
printf '%s\n' 'Gotovo: otvori GhostECC.xcworkspace, izaberi signing team i pokreni build/test.'
