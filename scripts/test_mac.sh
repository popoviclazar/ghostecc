#!/bin/bash
set -euo pipefail
project_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$project_root"
if [ ! -d GhostECC.xcworkspace ]; then
  echo 'Prvo pokreni scripts/setup_mac.sh.' >&2
  exit 1
fi
# Pass a simulator available on your Mac; xcodebuild -showdestinations lists them.
if [ "$#" -ne 1 ]; then
  echo 'Usage: scripts/test_mac.sh "platform=iOS Simulator,id=YOUR-SIMULATOR-UUID"' >&2
  exit 1
fi
xcodebuild -workspace GhostECC.xcworkspace -scheme GhostECC -destination "$1" \
  -derivedDataPath .build -resultBundlePath .build/TestResults.xcresult \
  CODE_SIGNING_ALLOWED=NO test
