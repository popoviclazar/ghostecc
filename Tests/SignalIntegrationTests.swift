import XCTest
@testable import GhostECC

final class SignalIntegrationTests: XCTestCase {
    private let reply = ReplyAddress(server: "https://relay.example.com", senderID: String(repeating: "R", count: 32))

    private func requireLibrary() throws {
        if !SignalEngine.available { throw XCTSkip("Instaliraj LibSignalClient preko scripts/setup_mac.sh i otvori xcworkspace.") }
    }
    private func identity(_ engine: SignalEngine) async throws -> (GhostID, Data) {
        let loaded = try await engine.loadIdentity(create: true)
        return try XCTUnwrap(loaded)
    }
    /// Bob invites, Alice joins with hello, Bob answers ready. Returns both engines with an established session.
    private func connected() async throws -> (alice: SignalEngine, a: (GhostID, Data), bob: SignalEngine, b: (GhostID, Data)) {
        let alice = SignalEngine(vault: nil), bob = SignalEngine(vault: nil)
        let a = try await identity(alice), b = try await identity(bob)
        try await alice.prepareSession(try await bob.invitationBundle())
        let hello = try await alice.encrypt(PrivatePayload.hello(sender: a.0, recipient: b.0, reply: reply))
        let opened = try await bob.decrypt(hello, expectedKey: nil)
        XCTAssertEqual(opened.payload.kind, .hello)
        XCTAssertEqual(opened.senderKey, a.1)
        let ready = try await bob.encrypt(PrivatePayload.ready(sender: b.0, recipient: a.0))
        let confirmed = try await alice.decrypt(ready, expectedKey: b.1)
        XCTAssertEqual(confirmed.payload.kind, .ready)
        return (alice, a, bob, b)
    }

    func testInvitationHandshakeAndBothDirections() async throws {
        try requireLibrary()
        let (alice, a, bob, b) = try await connected()
        let text = try PrivatePayload(sender: a.0, recipient: b.0, text: "Ghost ECC test")
        let received = try await bob.decrypt(try await alice.encrypt(text), expectedKey: a.1)
        XCTAssertEqual(received.payload.text, "Ghost ECC test")
        let photo = try PrivatePayload(sender: b.0, recipient: a.0, photo: Data([1, 2, 3]))
        let answer = try await alice.decrypt(try await bob.encrypt(photo), expectedKey: b.1)
        XCTAssertEqual(answer.payload.photo, Data([1, 2, 3]))
        let wav = WAV.wrap(pcm: Data((0..<64_000).map { UInt8($0 % 251) }))
        let voice = try await bob.decrypt(try await alice.encrypt(try PrivatePayload(sender: a.0, recipient: b.0, content: .voice(wav))), expectedKey: a.1)
        XCTAssertEqual(voice.payload.voice, wav)
        let file = FileAttachment(name: "notes.txt", type: "public.plain-text", data: Data("Ghost".utf8))
        let fileReply = try await alice.decrypt(try await bob.encrypt(try PrivatePayload(sender: b.0, recipient: a.0, content: .file(file))), expectedKey: b.1)
        XCTAssertEqual(fileReply.payload.file, file)
        let numberA = try await alice.safetyNumber(remoteID: b.0, remoteKey: b.1)
        let numberB = try await bob.safetyNumber(remoteID: a.0, remoteKey: a.1)
        XCTAssertEqual(numberA, numberB)
    }
    func testPaddingHidesTextLength() async throws {
        try requireLibrary()
        let (alice, a, _, b) = try await connected()
        let short = try await alice.encrypt(try PrivatePayload(sender: a.0, recipient: b.0, text: "a"))
        let long = try await alice.encrypt(try PrivatePayload(sender: a.0, recipient: b.0, text: String(repeating: "a", count: 600)))
        XCTAssertEqual(short.count, long.count)
    }
    func testInvitationQueueAcceptsOnlyHello() async throws {
        try requireLibrary()
        let alice = SignalEngine(vault: nil), bob = SignalEngine(vault: nil)
        let a = try await identity(alice), b = try await identity(bob)
        try await alice.prepareSession(try await bob.invitationBundle())
        let text = try await alice.encrypt(try PrivatePayload(sender: a.0, recipient: b.0, text: "skipping hello"))
        do { _ = try await bob.decrypt(text, expectedKey: nil); XCTFail("Content accepted on an invitation queue") } catch { }
    }
    func testOneTimeKeysAreConsumed() async throws {
        try requireLibrary()
        let alice = SignalEngine(vault: nil), bob = SignalEngine(vault: nil)
        let a = try await identity(alice), b = try await identity(bob)
        try await alice.prepareSession(try await bob.invitationBundle())
        let before = await bob.keyMaterialCounts()
        _ = try await bob.decrypt(try await alice.encrypt(PrivatePayload.hello(sender: a.0, recipient: b.0, reply: reply)), expectedKey: nil)
        let after = await bob.keyMaterialCounts()
        XCTAssertEqual(after.preKeys, before.preKeys - 1)
        XCTAssertEqual(after.kyberPreKeys, before.kyberPreKeys - 1)
        XCTAssertEqual(after.sessions, before.sessions + 1)
    }
    func testTamperingRejectedWithoutCorruptingRatchet() async throws {
        try requireLibrary()
        let (alice, a, bob, b) = try await connected()
        let cipher = try await alice.encrypt(try PrivatePayload(sender: a.0, recipient: b.0, text: "Original"))
        var altered = cipher; altered[altered.count - 1] ^= 1
        do { _ = try await bob.decrypt(altered, expectedKey: a.1); XCTFail("Tampered ciphertext accepted") } catch { }
        let valid = try await bob.decrypt(cipher, expectedKey: a.1)
        XCTAssertEqual(valid.payload.text, "Original")
        do { _ = try await bob.decrypt(cipher, expectedKey: a.1); XCTFail("Replay accepted") } catch { }
        do { _ = try await bob.decrypt(cipher, expectedKey: b.1); XCTFail("Wrong pinned key accepted") } catch { }
    }
    func testIdentityAndRatchetSurviveRestartWithoutHistory() async throws {
        try requireLibrary()
        let vault = KeychainVault(service: "ghost.tests." + UUID().uuidString)
        defer { try? vault.delete("signal-state") }
        let alice = SignalEngine(vault: nil), bob = SignalEngine(vault: vault)
        let a = try await identity(alice), b = try await identity(bob)
        try await alice.prepareSession(try await bob.invitationBundle())
        _ = try await bob.decrypt(try await alice.encrypt(PrivatePayload.hello(sender: a.0, recipient: b.0, reply: reply)), expectedKey: nil)
        let cipher = try await alice.encrypt(try PrivatePayload(sender: a.0, recipient: b.0, text: "NEVER-PERSIST-THIS-MESSAGE"))
        _ = try await bob.decrypt(cipher, expectedKey: a.1)
        let stored = try XCTUnwrap(vault.load("signal-state"))
        XCTAssertNil(stored.range(of: Data("NEVER-PERSIST-THIS-MESSAGE".utf8)))
        let restarted = SignalEngine(vault: vault)
        let reloaded = try await restarted.loadIdentity()
        XCTAssertEqual(try XCTUnwrap(reloaded).0, b.0)
        do { _ = try await restarted.decrypt(cipher, expectedKey: a.1); XCTFail("Replay after restart accepted") } catch { }
        let next = try await alice.encrypt(try PrivatePayload(sender: a.0, recipient: b.0, text: "Next"))
        let nextOpened = try await restarted.decrypt(next, expectedKey: a.1)
        XCTAssertEqual(nextOpened.payload.text, "Next")
    }
    func testForgedBundleIdentityIsRejected() async throws {
        try requireLibrary()
        let alice = SignalEngine(vault: nil), bob = SignalEngine(vault: nil)
        _ = try await identity(alice); _ = try await identity(bob)
        let b = try await bob.invitationBundle()
        let forged = KeyBundleDTO(id: b.id, registrationID: b.registrationID, deviceID: b.deviceID, identityKey: Data(repeating: 7, count: 33),
                                  preKey: b.preKey, signedPreKey: b.signedPreKey, kyberPreKey: b.kyberPreKey)
        do { try await alice.prepareSession(forged); XCTFail("Forged identity accepted") } catch { }
        let mallory = SignalEngine(vault: nil)
        _ = try await identity(mallory)
        let other = try await mallory.invitationBundle()
        let swapped = KeyBundleDTO(id: b.id, registrationID: b.registrationID, deviceID: 1, identityKey: b.identityKey,
                                   preKey: other.preKey, signedPreKey: other.signedPreKey, kyberPreKey: other.kyberPreKey)
        do { try await alice.prepareSession(swapped); XCTFail("Unsigned prekeys accepted") } catch { }
    }
    func testCancelledBundleCannotBeUsed() async throws {
        try requireLibrary()
        let alice = SignalEngine(vault: nil), bob = SignalEngine(vault: nil)
        let a = try await identity(alice), b = try await identity(bob)
        let bundle = try await bob.invitationBundle()
        try await bob.discardBundle(id: bundle.preKey.id)
        try await alice.prepareSession(bundle)
        let hello = try await alice.encrypt(PrivatePayload.hello(sender: a.0, recipient: b.0, reply: reply))
        do { _ = try await bob.decrypt(hello, expectedKey: nil); XCTFail("Cancelled invitation accepted") } catch { }
    }
    func testLocalLabDoesNotPersistConversationRatchet() async throws {
        try requireLibrary()
        let vault = KeychainVault(service: "ghost.tests." + UUID().uuidString)
        defer { try? vault.delete("signal-state") }
        let real = SignalEngine(vault: vault)
        let me = try await identity(real)
        let before = try XCTUnwrap(vault.load("signal-state"))
        let local = try await real.localTestClone()
        let peer = SignalEngine(vault: nil)
        let recipient = try await identity(peer)
        try await local.prepareSession(try await peer.invitationBundle())
        let encrypted = try await local.encrypt(try PrivatePayload(sender: me.0, recipient: recipient.0, text: "RAM-only lab"))
        _ = try await peer.decrypt(encrypted, expectedKey: me.1)
        XCTAssertEqual(before, try XCTUnwrap(vault.load("signal-state")))
    }
}
