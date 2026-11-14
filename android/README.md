# Ghost Talk for Android

Native Kotlin / Jetpack Compose app, protocol-compatible with the iOS app: same relay, same invitations,
same Signal sessions (libsignal 0.105.0 from Signal's Maven repository), so Android and iPhone users can
talk to each other and share groups.

## Status

Phase 1 of 6: identity, encryption, invitations and signed relay requests, with a diagnostics screen.
Next: chat interface, media, groups and forwarding, push notifications (Firebase), Google Play.

## Build

1. Install [Android Studio](https://developer.android.com/studio) (it includes the JDK).
2. **File → Open** and choose this `android` folder. The first sync downloads Gradle and all libraries,
   including libsignal from `build-artifacts.signal.org`.
3. **Tests:** in the Project view, right-click `app/src/test/java` → **Run 'Tests in …'**. They run on the
   computer (libsignal ships desktop native libraries), no phone needed.
4. **Phone:** enable Developer options (Settings → About phone → tap *Build number* seven times), turn on
   USB debugging, connect the phone, choose it at the top of Android Studio and press **Run**.

## Layout

| Path | Contents |
|---|---|
| `core/` | Ghost ID, payload and its validation, padding, invitations, JSON identical to iOS |
| `net/RelayClient.kt` | Signed relay requests (Ed25519 per mailbox) |
| `security/SignalEngine.kt` | The only file using libsignal; transactional protocol state |
| `security/Vault.kt` | Android Keystore AES-GCM storage in the no-backup directory |
