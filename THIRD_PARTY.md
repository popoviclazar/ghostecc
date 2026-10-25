# Third-party software

## libsignal (iOS)
- Source: https://github.com/signalapp/libsignal, pinned commit `4beb029d8a941f81e7d9c6d8af1ed25a677569a8` (version 0.105.0), downloaded and built by `scripts/setup_mac.sh`; not included in this repository.
- License: GNU AGPL v3.0, © Signal Messenger, LLC. Upstream notes that use outside Signal is unsupported and the API may change.

## Apple frameworks (iOS)
SwiftUI, Foundation, Security, LocalAuthentication, CryptoKit, AVFoundation, PhotosUI, VisionKit, UIKit, CoreImage, ImageIO, UniformTypeIdentifiers, UserNotifications.

## Relay server
- Node.js 20+ standard library only (`node:crypto`, `node:http`, `node:http2`, `node:fs`); no npm dependencies.
- Caddy (Apache-2.0) as the TLS reverse proxy, installed separately.
- Python `cryptography` is used only by the test `server/test/crosscheck.py`.

## Artwork
The app icon and the ghost mark are drawn programmatically for this project.

SimpleX Chat and Session were used only as architectural references; no code, assets or text were copied.
