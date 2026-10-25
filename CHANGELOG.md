# Changelog

## 1.0.0

First public release.

- One-time invitations (QR code or link) and anonymous relay mailboxes; no accounts, phone numbers or Ghost IDs on the server.
- End-to-end encryption with libsignal: PQXDH and the Triple Ratchet (Double Ratchet + SPQR).
- Contact verification by safety number, by eye or by scanning a QR code in person.
- Text, photos (metadata stripped), voice messages up to 90 seconds and files up to 4 MB, all in memory only, expiring after at most 24 hours.
- Face ID / passcode lock, hiding during screen recording, optional wipe of chats when leaving the app.
- Optional notifications that only say "New message"; in-app sound and unread badges.
- Ghost Lab for trying encryption without a second person.
- English and Serbian.
- Relay server: Node.js without dependencies, RAM-only messages, APNs support, one-command Ubuntu installer.
