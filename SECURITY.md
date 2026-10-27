# Security

## Reporting a vulnerability

Email **popoviclazar65@gmail.com** with a description and, if possible, steps to reproduce. Please give a reasonable time to fix the issue before publishing it. Never send private keys.

Ghost ECC has **not yet had an independent security audit**.

## Cryptography

- **Session setup:** PQXDH (X25519 + ML-KEM), with one-time prekeys created for each invitation. libsignal rejects legacy X3DH without the post-quantum part.
- **Ongoing messages:** Signal's Triple Ratchet: the Double Ratchet (X25519) together with the post-quantum SPQR ratchet (ML-KEM 768), enabled by default in libsignal since 0.83. An attacker would have to break both elliptic curves and ML-KEM.
- **Identity:** a Ghost ID is the SHA-256 of the identity key, so a contact's key cannot be replaced without detection. Users verify each other with a 60-digit safety number, compared by eye or by scanning a QR code in person; the app sends no content until a contact is verified.
- **Invitations:** the one-time prekey bundle stored on the relay is encrypted with AES-GCM under a key that exists only in the invitation link, and bound to the inviter's identity key. The relay can neither read nor swap it.
- **Relay requests:** each mailbox has its own Ed25519 key; every request is signed over the operation, mailbox, timestamp, nonce, relay origin and body digest, with replay protection.
- **Transport:** HTTPS with TLS 1.3. Plaintext is padded to fixed size buckets before encryption so message length is not visible.
- No custom cryptography: libsignal and Apple CryptoKit only.

## What Ghost ECC protects

- **Message content** from the relay operator, the network and anyone without the device keys.
- **Who talks to whom** from the relay as far as identities go: no accounts, no directory, no Ghost IDs on the server; the sender exists only inside the ciphertext.
- **Unwanted contact:** only someone holding your one-time invitation can reach you; the first valid sender locks the mailbox to their key.
- **On the device:** keys and contacts in the Keychain (`WhenUnlockedThisDeviceOnly`, never synced); messages, photos, voice messages and files only in memory; Face ID / passcode lock; content hidden in the app switcher and during screen recording; optional wipe of all chats when leaving the app; third-party keyboards blocked; photo metadata stripped.

## App passcode

Optional, under Privacy → Device. With a passcode set, the device passcode no longer opens Ghost ECC; Face ID / Touch ID can stay enabled as a shortcut. The passcode (6–16 digits) is never stored: only a verifier, PBKDF2-SHA256 with 400,000 iterations and a random salt, bound through HMAC to a key inside the Secure Enclave where available, so guesses have to be made on the phone itself. Waiting time grows after 5 wrong attempts up to one hour, and an optional setting erases the identity after 10. If someone adds a face or finger to the phone, biometrics stop opening the app until the passcode is entered. The passcode controls access to the app; the keys themselves remain protected by the iOS Keychain.

## What it does not protect

- **Network metadata:** the relay sees IP addresses, timing, padded packet sizes and which mailboxes one client polls together. There is no onion routing; a VPN or Tor reduces this.
- **A compromised phone:** spyware controlling iOS can read the screen and keyboard.
- **The other person:** your contact can photograph the screen or share what you sent. iOS cannot reliably block all screenshots.
- **Forensic erasure:** memory and Keychain are cleared through iOS APIs, without a guarantee of physical erasure.
- **Availability:** messages exist for 24 hours at most and are lost earlier if the app or relay restarts.

## Push notifications

Optional and off until the user allows them. To send one, the relay keeps a link between the device's APNs token and its mailboxes, in memory only. Apple sees that a notification reached the device; the notification always says only "New message".
