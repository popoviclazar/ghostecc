import XCTest
import CryptoKit
@testable import GhostECC

final class PrivacyRulesTests: XCTestCase {
    private let alice = GhostID(identityKey: Data(repeating: 1, count: 33))
    private let bob = GhostID(identityKey: Data(repeating: 2, count: 33))
    private let queueID = String(repeating: "A", count: 32)

    func testInvalidIDsAreRejectedIncludingDecodedIDs() throws {
        for input in ["", "GHOST-00", "GHOST-" + String(repeating: "Z", count: 64), "someone"] {
            XCTAssertThrowsError(try GhostID(input))
            let data = try JSONEncoder().encode(input)
            XCTAssertThrowsError(try WireCodec.decoder().decode(GhostID.self, from: data))
        }
        XCTAssertEqual(try GhostID(alice.rawValue.lowercased()), alice)
    }
    func testMaximumLifetimeAndExpiry() throws {
        let now = Date(timeIntervalSince1970: 1_000_000)
        let payload = try PrivatePayload(sender: alice, recipient: bob, text: "Test", now: now)
        XCTAssertEqual(payload.expiresAt.timeIntervalSince(now), 86_400)
        XCTAssertThrowsError(try payload.validate(sender: alice, recipient: bob, now: payload.expiresAt))
        XCTAssertThrowsError(try PrivatePayload(sender: alice, recipient: bob, text: "Test", lifetime: 86_401, now: now))
        XCTAssertThrowsError(try PrivatePayload(sender: alice, recipient: bob, text: "Test", lifetime: 0, now: now))
    }
    func testRollbackCannotExtendLoadedMessage() throws {
        let now = Date()
        let payload = try PrivatePayload(sender: alice, recipient: bob, text: "Test", lifetime: 300, now: now)
        let message = payload.display(outgoing: true, status: .local, now: now)
        let rollback = now.addingTimeInterval(-3600)
        XCTAssertEqual(message.remaining(now: rollback, uptime: message.receivedUptime + 301), 0)
    }
    func testAddressBindingAndContentLimits() throws {
        let payload = try PrivatePayload(sender: alice, recipient: bob, text: "Test")
        XCTAssertEqual(payload.kind, .text)
        XCTAssertThrowsError(try payload.validate(sender: bob, recipient: alice))
        XCTAssertThrowsError(try PrivatePayload(sender: alice, recipient: bob, text: " "))
        XCTAssertThrowsError(try PrivatePayload(sender: alice, recipient: bob, text: "x", photo: Data([1])))
        XCTAssertThrowsError(try PrivatePayload(sender: alice, recipient: bob, photo: Data(repeating: 0, count: Limits.maxPhotoBytes + 1)))
    }
    func testControlPayloadRules() throws {
        let hello = PrivatePayload.hello(sender: alice, recipient: bob, reply: ReplyAddress(server: "https://relay.example.com", senderID: queueID))
        XCTAssertEqual(hello.kind, .hello)
        XCTAssertNoThrow(try hello.validate(sender: alice, recipient: bob))
        let insecure = PrivatePayload.hello(sender: alice, recipient: bob, reply: ReplyAddress(server: "http://relay.example.com", senderID: queueID))
        XCTAssertThrowsError(try insecure.validate(sender: alice, recipient: bob))
        let badQueue = PrivatePayload.hello(sender: alice, recipient: bob, reply: ReplyAddress(server: "https://relay.example.com", senderID: "short"))
        XCTAssertThrowsError(try badQueue.validate(sender: alice, recipient: bob))
        let ready = PrivatePayload.ready(sender: alice, recipient: bob)
        XCTAssertNoThrow(try ready.validate(sender: alice, recipient: bob))
    }
    func testPaddingHidesLengthAndRoundTrips() throws {
        let short = WirePadding.pad(Data("hi".utf8)), longer = WirePadding.pad(Data(repeating: 65, count: 900))
        XCTAssertEqual(short.count, 1_024)
        XCTAssertEqual(longer.count, 1_024)
        XCTAssertEqual(try WirePadding.unpad(short), Data("hi".utf8))
        XCTAssertEqual(WirePadding.pad(Data(repeating: 1, count: 5_000)).count, 16_384)
        XCTAssertEqual(WirePadding.pad(Data(repeating: 1, count: 70_000)).count, 262_144)
        XCTAssertThrowsError(try WirePadding.unpad(Data([0, 0, 9, 0])))
    }
    func testWireEnvelopeFormat() throws {
        let envelope = WireEnvelope(messageType: 2, ciphertext: Data([1, 2, 3]))
        XCTAssertEqual(envelope.bytes, Data([2, 2, 1, 2, 3]))
        XCTAssertEqual(try WireEnvelope(bytes: envelope.bytes), envelope)
        XCTAssertThrowsError(try WireEnvelope(bytes: Data([1, 2, 3])))
    }
    func testInviteLinkValidation() throws {
        let link = InviteLink(v: 1, s: "https://relay.example.com", q: queueID, k: Data(repeating: 5, count: 33), x: Data(repeating: 9, count: 32))
        let parsed = try InviteLink.parse(link.string())
        XCTAssertEqual(parsed, link)
        XCTAssertEqual(parsed.ghostID, GhostID(identityKey: link.k))
        XCTAssertLessThan(try link.string().count, 400)
        XCTAssertThrowsError(try InviteLink.parse(InviteLink(v: 1, s: "http://relay.example.com", q: queueID, k: link.k, x: link.x).string()))
        XCTAssertThrowsError(try InviteLink.parse(InviteLink(v: 1, s: link.s, q: queueID, k: Data(repeating: 5, count: 32), x: link.x).string()))
        XCTAssertThrowsError(try InviteLink.parse(InviteLink(v: 1, s: link.s, q: "../x", k: link.k, x: link.x).string()))
        XCTAssertThrowsError(try InviteLink.parse("ghost-ecc://contact/abc"))
    }
    func testInviteBundleIsBoundToLinkKeyAndIdentity() throws {
        let identity = Data(repeating: 5, count: 33)
        let bundle = KeyBundleDTO(id: GhostID(identityKey: identity), registrationID: 7, deviceID: 1, identityKey: identity,
                                  preKey: PublicPreKey(id: 1, key: Data([1])), signedPreKey: PublicSignedPreKey(id: 1, key: Data([2]), signature: Data([3])),
                                  kyberPreKey: PublicSignedPreKey(id: 1, key: Data([4]), signature: Data([5])))
        let key = SecureRandom.bytes(32)
        let sealed = try InviteCrypto.seal(bundle, key: key)
        let link = InviteLink(v: 1, s: "https://relay.example.com", q: queueID, k: identity, x: key)
        XCTAssertEqual(try InviteCrypto.open(sealed, link: link), bundle)
        XCTAssertThrowsError(try InviteCrypto.open(sealed, link: InviteLink(v: 1, s: link.s, q: queueID, k: identity, x: SecureRandom.bytes(32))))
        XCTAssertThrowsError(try InviteCrypto.open(sealed, link: InviteLink(v: 1, s: link.s, q: queueID, k: Data(repeating: 6, count: 33), x: key)))
    }
    func testRelayOriginNormalization() throws {
        XCTAssertEqual(try RelayOrigin.normalize("HTTPS://Relay.Example.com/"), "https://relay.example.com")
        XCTAssertEqual(try RelayOrigin.normalize("https://relay.example.com:443"), "https://relay.example.com")
        XCTAssertEqual(try RelayOrigin.normalize("https://relay.example.com:8443"), "https://relay.example.com:8443")
        for bad in ["http://relay.example.com", "https://user:pw@relay.example.com", "https://relay.example.com/path", "https://relay.example.com?x=1", "relay.example.com"] {
            XCTAssertThrowsError(try RelayOrigin.normalize(bad), bad)
        }
        XCTAssertNoThrow(try RelayClient(origin: "https://relay.example.com"))
        XCTAssertThrowsError(try RelayClient(origin: "http://relay.example.com"))
    }
    func testRelaySigningMatchesServerVector() throws {
        // Same vector as server/test/relay.test.js and docs/RELAY-PROTOCOL.md.
        let digest = RelaySigning.digest(Data("hello".utf8))
        XCTAssertEqual(digest, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        let message = RelaySigning.message(origin: "https://relay.example.com", op: "fetch", queueID: "Q", timestamp: 1_700_000_000_000, nonce: "N", digest: digest)
        XCTAssertEqual(String(decoding: message, as: UTF8.self), "GHOST-RELAY-v1\nhttps://relay.example.com\nfetch\nQ\n1700000000000\nN\n" + digest)
        let key = Curve25519.Signing.PrivateKey()
        let signature = try key.signature(for: message)
        XCTAssertEqual(signature.count, 64)
        XCTAssertTrue(key.publicKey.isValidSignature(signature, for: message))
        XCTAssertEqual(SecureRandom.bytes(16).base64URLEncoded.count, 22)
    }
    func testWAVHeaderAndDuration() {
        let wav = WAV.wrap(pcm: Data(repeating: 0, count: 32_000))
        XCTAssertEqual(wav.count, 32_044)
        XCTAssertTrue(WAV.isValid(wav))
        XCTAssertEqual(WAV.duration(of: wav), 1.0, accuracy: 0.001)
        XCTAssertFalse(WAV.isValid(Data(repeating: 1, count: 100)))
        XCTAssertEqual(WAV.duration(of: Data([1, 2, 3])), 0)
    }
    func testVoiceAndFilePayloadRules() throws {
        let wav = WAV.wrap(pcm: Data(repeating: 0, count: 16_000))
        let voice = try PrivatePayload(sender: alice, recipient: bob, content: .voice(wav))
        XCTAssertEqual(voice.kind, .voice)
        XCTAssertNoThrow(try voice.validate(sender: alice, recipient: bob))
        XCTAssertEqual(voice.content, .voice(wav))
        XCTAssertThrowsError(try PrivatePayload(sender: alice, recipient: bob, content: .voice(Data(repeating: 1, count: 500))))
        XCTAssertThrowsError(try PrivatePayload(sender: alice, recipient: bob, content: .voice(WAV.wrap(pcm: Data(count: Limits.maxVoiceBytes)))))
        let file = FileAttachment(name: "racun.pdf", type: "com.adobe.pdf", data: Data([1, 2, 3]))
        let filePayload = try PrivatePayload(sender: alice, recipient: bob, content: .file(file))
        XCTAssertNoThrow(try filePayload.validate(sender: alice, recipient: bob))
        XCTAssertThrowsError(try PrivatePayload(sender: alice, recipient: bob, content: .file(FileAttachment(name: "../x", type: "public.data", data: Data([1])))))
        XCTAssertThrowsError(try PrivatePayload(sender: alice, recipient: bob, content: .file(FileAttachment(name: "big.bin", type: "public.data", data: Data(count: Limits.maxFileBytes + 1)))))
        XCTAssertEqual(FileAttachment.cleanName("../../etc/passwd"), "_.._etc_passwd")
        XCTAssertEqual(FileAttachment.cleanName("  "), "file")
    }
    func testMixedContentIsRejected() throws {
        let text = try PrivatePayload(sender: alice, recipient: bob, text: "hi")
        var json = try JSONSerialization.jsonObject(with: WireCodec.encoder().encode(text)) as! [String: Any]
        json["voice"] = WAV.wrap(pcm: Data(count: 3200)).base64EncodedString()
        let forged = try WireCodec.decoder().decode(PrivatePayload.self, from: JSONSerialization.data(withJSONObject: json))
        XCTAssertThrowsError(try forged.validate(sender: alice, recipient: bob))
    }
    func testSafetyCodeQR() {
        let number = String(repeating: "12345 ", count: 12)
        let link = SafetyCode.link(number)
        XCTAssertEqual(link, "ghost-ecc://verify/" + String(repeating: "12345", count: 12))
        XCTAssertTrue(SafetyCode.matches(link, number))
        XCTAssertFalse(SafetyCode.matches(link + "0", number))
        XCTAssertFalse(SafetyCode.matches(SafetyCode.link(String(repeating: "54321 ", count: 12)), number))
        XCTAssertFalse(SafetyCode.matches(SafetyCode.link("123"), "123"))
    }
    func testDisplayFormatting() {
        let id = GhostID(identityKey: Data(repeating: 9, count: 33))
        let lines = IdentityView.grouped(id).split(separator: "\n")
        XCTAssertEqual(lines.count, 4)
        XCTAssertTrue(lines.allSatisfy { $0.split(separator: " ").count == 4 })
        XCTAssertEqual(MessageMeta.remaining(7_200), "2 h")
        XCTAssertEqual(MessageMeta.remaining(125), "2 min")
        XCTAssertEqual(MessageMeta.remaining(9), "9 s")
    }
    func testNotifyDigestMatchesServerVector() {
        // Same vector as server/test/push.test.js.
        XCTAssertEqual(String(decoding: RelayClient.notifyDigestInput(token: "ab", environment: "sandbox"), as: UTF8.self), "ab|sandbox")
        XCTAssertEqual(String(decoding: RelayClient.notifyDigestInput(token: nil, environment: "production"), as: UTF8.self), "|production")
    }
    func testSettingsFromOlderVersionStillLoad() throws {
        let old = Data(#"{"lockEnabled":false,"hideDuringCapture":true,"lifetime":3600,"serverURL":"https://relay.example.com"}"#.utf8)
        let settings = try WireCodec.decoder().decode(AppSettings.self, from: old)
        XCTAssertFalse(settings.lockEnabled)
        XCTAssertEqual(settings.lifetime, 3600)
        XCTAssertFalse(settings.notificationsEnabled)
        let unset = try WireCodec.decoder().decode(AppSettings.self, from: Data(#"{"serverURL":""}"#.utf8))
        XCTAssertEqual(unset.serverURL, AppConfig.defaultServer)
        XCTAssertEqual(try RelayOrigin.normalize(AppConfig.defaultServer), AppConfig.defaultServer)
        var updated = settings; updated.notificationsEnabled = true
        XCTAssertEqual(try WireCodec.decoder().decode(AppSettings.self, from: WireCodec.encoder().encode(updated)), updated)
    }
}
