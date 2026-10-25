#if canImport(LibSignalClient)
import Foundation
import LibSignalClient

struct SignalSnapshot: Codable {
    var identity: Data
    var registrationID: UInt32
    var identities: [String: Data] = [:]
    var sessions: [String: Data] = [:]
    var preKeys: [String: Data] = [:]
    var signedPreKeys: [String: Data] = [:]
    var kyberPreKeys: [String: Data] = [:]
    var usedKyberBases: [String: [Data]] = [:]
    var issuedAt: [String: Date] = [:]
}

// Confined to SignalEngine's actor. Library callbacks mutate a value snapshot;
// one Keychain update commits the whole protocol operation before ciphertext leaves the actor.
final class SignalStore: IdentityKeyStore, SessionStore, PreKeyStore, SignedPreKeyStore, KyberPreKeyStore {
    static let bundleRetention: TimeInterval = 8 * 86_400
    var state: SignalSnapshot
    init(state: SignalSnapshot) { self.state = state }
    private func addressKey(_ a: ProtocolAddress) -> String { a.name + "." + String(a.deviceId) }
    func identityKeyPair(context: StoreContext) throws -> IdentityKeyPair { try IdentityKeyPair(bytes: state.identity) }
    func localRegistrationId(context: StoreContext) throws -> UInt32 { state.registrationID }
    func identity(for address: ProtocolAddress, context: StoreContext) throws -> IdentityKey? {
        try state.identities[addressKey(address)].map { try IdentityKey(bytes: $0) }
    }
    func isTrustedIdentity(_ identity: IdentityKey, for address: ProtocolAddress, direction: Direction, context: StoreContext) throws -> Bool {
        guard GhostID(identityKey: identity.serialize()).rawValue == address.name else { return false }
        if let stored = state.identities[addressKey(address)] { return stored == identity.serialize() }
        return true // Key-bound IDs: an address can only ever belong to the key it was derived from.
    }
    func saveIdentity(_ identity: IdentityKey, for address: ProtocolAddress, context: StoreContext) throws -> IdentityChange {
        guard try isTrustedIdentity(identity, for: address, direction: .sending, context: context) else { throw GhostError.keyChanged }
        state.identities[addressKey(address)] = identity.serialize(); return .newOrUnchanged
    }
    func loadSession(for address: ProtocolAddress, context: StoreContext) throws -> SessionRecord? {
        try state.sessions[addressKey(address)].map { try SessionRecord(bytes: $0) }
    }
    func loadExistingSessions(for addresses: [ProtocolAddress], context: StoreContext) throws -> [SessionRecord] {
        try addresses.map { guard let record = try loadSession(for: $0, context: context) else { throw GhostError.invalidPayload }; return record }
    }
    func storeSession(_ record: SessionRecord, for address: ProtocolAddress, context: StoreContext) throws {
        let key = addressKey(address)
        guard state.sessions[key] != nil || state.sessions.count < Limits.maxContacts + Limits.maxInvites else { throw GhostError.limit }
        state.sessions[key] = record.serialize()
    }
    func loadPreKey(id: UInt32, context: StoreContext) throws -> PreKeyRecord {
        guard let bytes = state.preKeys[String(id)] else { throw GhostError.invalidPayload }; return try PreKeyRecord(bytes: bytes)
    }
    func storePreKey(_ record: PreKeyRecord, id: UInt32, context: StoreContext) throws { state.preKeys[String(id)] = record.serialize() }
    func removePreKey(id: UInt32, context: StoreContext) throws { state.preKeys.removeValue(forKey: String(id)) }
    func loadSignedPreKey(id: UInt32, context: StoreContext) throws -> SignedPreKeyRecord {
        guard let bytes = state.signedPreKeys[String(id)] else { throw GhostError.invalidPayload }; return try SignedPreKeyRecord(bytes: bytes)
    }
    func storeSignedPreKey(_ record: SignedPreKeyRecord, id: UInt32, context: StoreContext) throws { state.signedPreKeys[String(id)] = record.serialize() }
    func loadKyberPreKey(id: UInt32, context: StoreContext) throws -> KyberPreKeyRecord {
        guard let bytes = state.kyberPreKeys[String(id)] else { throw GhostError.invalidPayload }; return try KyberPreKeyRecord(bytes: bytes)
    }
    func storeKyberPreKey(_ record: KyberPreKeyRecord, id: UInt32, context: StoreContext) throws { state.kyberPreKeys[String(id)] = record.serialize() }
    func markKyberPreKeyUsed(id: UInt32, signedPreKeyId: UInt32, baseKey: PublicKey, context: StoreContext) throws {
        let key = String(id) + "." + String(signedPreKeyId)
        let bytes = baseKey.serialize()
        guard !(state.usedKyberBases[key] ?? []).contains(bytes) else { throw GhostError.invalidPayload }
        state.usedKyberBases[key, default: []].append(bytes)
        // Every Ghost ECC Kyber prekey belongs to exactly one invitation, so it is one-time and deleted after use.
        state.kyberPreKeys.removeValue(forKey: String(id))
    }
    func discardBundle(id: UInt32) {
        let key = String(id)
        state.preKeys.removeValue(forKey: key); state.signedPreKeys.removeValue(forKey: key); state.kyberPreKeys.removeValue(forKey: key)
        state.usedKyberBases.removeValue(forKey: key + "." + key); state.issuedAt.removeValue(forKey: key)
    }
    func prunePreKeys(now: Date) {
        for (id, issued) in state.issuedAt where now.timeIntervalSince(issued) >= Self.bundleRetention {
            if let number = UInt32(id) { discardBundle(id: number) }
        }
    }
    func forget(name: String) {
        let key = name + ".1"
        state.sessions.removeValue(forKey: key); state.identities.removeValue(forKey: key)
    }
}
#endif
