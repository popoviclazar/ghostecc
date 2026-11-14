# Changelog

## 1.1.1

- Ghost ECC is now called **Ghost Talk**. Nothing else changes: same app, keys, contacts, server and invitation links.
- Group chats of up to 20 members. The admin adds verified contacts; each gets an invitation to accept or decline. Every group message is encrypted separately for each member over the pairwise Signal sessions, so the relay never learns that a group exists.
- Members who don't know each other are connected automatically through the admin with one-time invitations that only the intended member can use. These connections are marked "connected through the group" and need their own safety-number check before one-to-one chats.
- Forwarding: long-press a message to send a copy to other chats; each copy is encrypted for its recipients and marked "Forwarded".
- Ghost Lab group: try groups and forwarding on a single device (Privacy → Ghost Lab).
- Recommend Ghost Talk and rate it on the App Store from the About screen.
- Reply to a message (with a quote), react with an emoji, and delete your own messages for everyone.
- Message lifetime per chat, and muting a contact (its mailbox leaves push registration on the relay).
- The app icon shows the number of new messages since the app was last opened.
- The app is now English only, whatever the phone language; the language option was removed.

## 1.0.0

First public release.

- One-time invitations (QR code or link) and anonymous relay mailboxes; no accounts, phone numbers or Ghost IDs on the server.
- End-to-end encryption with libsignal: PQXDH and the Triple Ratchet (Double Ratchet + SPQR).
- Contact verification by safety number, by eye or by scanning a QR code in person.
- Text, photos (metadata stripped), voice messages up to 90 seconds and files up to 4 MB, all in memory only, expiring after at most 24 hours.
- Face ID / passcode lock, optional app passcode separate from the phone passcode (escalating delays, optional wipe after 10 wrong attempts), hiding during screen recording, optional wipe of chats when leaving the app.
- Optional notifications that only say "New message"; in-app sound and unread badges.
- Ghost Lab for trying encryption without a second person.
- English and Serbian.
- Relay server: Node.js without dependencies, RAM-only messages, APNs support, one-command Ubuntu installer.
