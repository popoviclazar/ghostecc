# Ghost ECC

**Private messages without a phone number.** Ghost ECC is an iOS messenger with no accounts, no phone numbers and no address book. Contacts are added only with a one-time invitation, everything is end-to-end encrypted with [libsignal](https://github.com/signalapp/libsignal), and messages disappear within 24 hours without ever being written to disk.

## Features

- **No account:** your Ghost ID is created on your iPhone and never leaves it.
- **Invitation only:** a contact is added with a one-time QR code or link. Nobody can message you without an invitation you gave them, so there is no spam from strangers.
- **End-to-end encryption:** the Signal Protocol with post-quantum protection (PQXDH and the SPQR ratchet), via libsignal.
- **Verify in person:** scan each other's safety code (or compare the 60-digit number). The app sends nothing until the contact is verified, and a contact's key can never change silently.
- **Disappearing by design:** messages, photos, voice messages and files live only in memory, for 24 hours at most (or 1 hour, or 5 minutes).
- **Device protection:** Face ID or an optional app passcode (with optional wipe after 10 wrong attempts), content hidden in the app switcher and during screen recording, optional wipe of all chats when leaving the app, photo metadata (EXIF/GPS) stripped before sending.
- **Quiet notifications:** if enabled, a notification only ever says "New message", with no name or content.
- **Ghost Lab:** try encrypted messaging on your own, without a second person.
- English and Serbian.

## How it works

1. Your phone creates a one-time invitation: a private mailbox on the relay, holding encrypted one-time keys. The QR code or link carries the key that opens them.
2. Your contact scans it, starts a Signal session and answers through a mailbox of their own. The invitation is then used up.
3. From then on each side reads only its own mailbox, signing every request with that mailbox's key.

The relay never learns Ghost IDs or identity keys. It sees random mailbox IDs, IP addresses, timing and the size of padded encrypted packets. Message bodies are kept only in the relay's memory until delivered, for 24 hours at most.

More detail: [Security model](SECURITY.md) · [Relay protocol](docs/RELAY-PROTOCOL.md) · [Server data](docs/SERVER.md) · [Privacy policy](https://popoviclazar.github.io/ghostecc/privacy.html)

## Repository

| Path | Contents |
|---|---|
| `GhostECC/` | iOS app (SwiftUI, iOS 17+) |
| `Tests/` | Unit and libsignal integration tests |
| `server/` | Relay server (Node.js, no dependencies) and deployment files |
| `docs/` | Protocol specification, API (OpenAPI) and build instructions |
| `scripts/` | Setup, localization, project generation and validation |

- **Build the app from source:** [docs/BUILDING.md](docs/BUILDING.md)
- **Run your own relay:** [server/README.md](server/README.md)

## Security

Please report vulnerabilities privately to **popoviclazar65@gmail.com** before publishing them. Ghost ECC has not yet had an independent security audit; see [SECURITY.md](SECURITY.md) for what it does and does not protect against.

## License

Ghost ECC is free software under the [GNU Affero General Public License v3.0](LICENSE). It uses libsignal by Signal Messenger, LLC, also licensed under the AGPL v3.0. Ghost ECC is not a Signal product and is not endorsed by Signal. See [THIRD_PARTY.md](THIRD_PARTY.md).

---

### Srpski

Ghost ECC je messenger za iPhone bez naloga, broja telefona i imenika. Kontakti se dodaju samo jednokratnom pozivnicom, sve je šifrovano s kraja na kraj pomoću libsignal-a (uključujući post-kvantnu zaštitu), a poruke nestaju za najviše 24 sata i nikad se ne upisuju na disk. Kontakt potvrđujete skeniranjem sigurnosnog koda uživo. Aplikacija je na srpskom i engleskom. Podrška i prijava ranjivosti: popoviclazar65@gmail.com · [Politika privatnosti](https://popoviclazar.github.io/ghostecc/privacy.html)
