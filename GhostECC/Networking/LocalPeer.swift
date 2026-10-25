import Foundation

// A second, independent Signal endpoint on the same device. No network requests.
// Both directions run through the same SignalEngine code paths as real contacts.
actor LocalPeer {
    private let engine = SignalEngine(vault: nil)
    private var identity: (GhostID, Data)?
    func contact() async throws -> Contact {
        guard let local = try await engine.loadIdentity(create: true) else { throw GhostError.cryptoUnavailable }
        identity = local
        return Contact(ghostID: local.0, name: "Ghost Lab", identityKey: local.1, verified: true, isDemo: true, state: .connected)
    }
    func bundle() async throws -> KeyBundleDTO { try await engine.invitationBundle() }
    func respond(to wire: Data, senderKey: Data) async throws -> Data {
        guard let identity else { throw GhostError.invalidPayload }
        let opened = try await engine.decrypt(wire, expectedKey: senderKey)
        let lifetime = max(1, min(PrivatePayload.maxLifetime, opened.payload.expiresAt.timeIntervalSinceNow))
        guard let content = opened.payload.content else { throw GhostError.invalidPayload }
        // Text is echoed with a prefix; photos, voice messages and files come back unchanged.
        var echo = content
        if case .text(let text) = content, text.utf8.count <= Limits.maxTextBytes - 64 {
            echo = .text(String(localized: "Primljeno u lokalnom testu: \(text)"))
        }
        let reply = try PrivatePayload(sender: identity.0, recipient: opened.payload.sender, content: echo, lifetime: lifetime)
        return try await engine.encrypt(reply)
    }
}
