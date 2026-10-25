import Foundation
#if canImport(LibSignalClient)
import LibSignalClient
#endif

actor SignalEngine {
    static var available: Bool {
        #if canImport(LibSignalClient)
        return true
        #else
        return false
        #endif
    }
    static let maxUnusedBundles = 32
    private let vault: KeychainVault?
    #if canImport(LibSignalClient)
    private var store: SignalStore?
    #endif
    init(vault: KeychainVault? = KeychainVault()) { self.vault = vault }

    /// Same identity, separate RAM-only protocol state. Used by Ghost Lab so the local test never touches the real ratchet.
    func localTestClone() throws -> SignalEngine {
        #if canImport(LibSignalClient)
        guard let store else { throw GhostError.cryptoUnavailable }
        return SignalEngine(snapshot: SignalSnapshot(identity: store.state.identity, registrationID: store.state.registrationID))
        #else
        throw GhostError.cryptoUnavailable
        #endif
    }
    #if canImport(LibSignalClient)
    private init(snapshot: SignalSnapshot) {
        self.vault = nil
        self.store = SignalStore(state: snapshot)
    }
    #endif

    func loadIdentity(create: Bool = false) throws -> (GhostID, Data)? {
        #if canImport(LibSignalClient)
        if store == nil {
            if let data = try vault?.load("signal-state") {
                store = SignalStore(state: try WireCodec.decoder().decode(SignalSnapshot.self, from: data))
            } else if create {
                let pair = IdentityKeyPair.generate()
                store = SignalStore(state: SignalSnapshot(identity: pair.serialize(), registrationID: UInt32.random(in: 1...0x3FFF)))
                do { try commit() } catch { store = nil; throw error }
            }
        }
        guard let store else { return nil }
        let pair = try store.identityKeyPair(context: NullContext())
        let key = pair.identityKey.serialize()
        return (GhostID(identityKey: key), key)
        #else
        if create { throw GhostError.cryptoUnavailable }; return nil
        #endif
    }

    /// A fresh one-time bundle for exactly one invitation. Its private halves stay in the Keychain snapshot.
    func invitationBundle() throws -> KeyBundleDTO {
        #if canImport(LibSignalClient)
        guard let store, let local = try loadIdentity() else { throw GhostError.cryptoUnavailable }
        return try transaction {
            store.prunePreKeys(now: Date())
            guard store.state.preKeys.count < Self.maxUnusedBundles, store.state.issuedAt.count < 256 else { throw GhostError.limit }
            var id = UInt32.random(in: 1...UInt32.max - 1)
            while store.state.issuedAt[String(id)] != nil { id = UInt32.random(in: 1...UInt32.max - 1) }
            let identity = try store.identityKeyPair(context: NullContext())
            let pre = PrivateKey.generate(); let signed = PrivateKey.generate(); let kyber = KEMKeyPair.generate()
            let signedSignature = identity.privateKey.generateSignature(message: signed.publicKey.serialize())
            let kyberSignature = identity.privateKey.generateSignature(message: kyber.publicKey.serialize())
            let timestamp = UInt64(Date().timeIntervalSince1970 * 1000)
            try store.storePreKey(PreKeyRecord(id: id, privateKey: pre), id: id, context: NullContext())
            try store.storeSignedPreKey(SignedPreKeyRecord(id: id, timestamp: timestamp, privateKey: signed, signature: signedSignature), id: id, context: NullContext())
            try store.storeKyberPreKey(KyberPreKeyRecord(id: id, timestamp: timestamp, keyPair: kyber, signature: kyberSignature), id: id, context: NullContext())
            store.state.issuedAt[String(id)] = Date()
            return KeyBundleDTO(id: local.0, registrationID: store.state.registrationID, deviceID: 1, identityKey: local.1,
                                preKey: PublicPreKey(id: id, key: pre.publicKey.serialize()),
                                signedPreKey: PublicSignedPreKey(id: id, key: signed.publicKey.serialize(), signature: signedSignature),
                                kyberPreKey: PublicSignedPreKey(id: id, key: kyber.publicKey.serialize(), signature: kyberSignature))
        }
        #else
        throw GhostError.cryptoUnavailable
        #endif
    }

    /// Removes the private keys of a cancelled or expired invitation.
    func discardBundle(id: UInt32) throws {
        #if canImport(LibSignalClient)
        guard let store else { return }
        try transaction { store.discardBundle(id: id) }
        #endif
    }

    func prepareSession(_ dto: KeyBundleDTO) throws {
        #if canImport(LibSignalClient)
        guard let store, let local = try loadIdentity(), dto.deviceID == 1,
              GhostID(identityKey: dto.identityKey) == dto.id, dto.id != local.0 else { throw GhostError.keyChanged }
        let address = try ProtocolAddress(name: dto.id.rawValue, deviceId: 1)
        // Do not reset an existing ratchet when the same bundle is processed again.
        if let session = try store.loadSession(for: address, context: NullContext()), session.hasCurrentState { return }
        let bundle = try PreKeyBundle(registrationId: dto.registrationID, deviceId: dto.deviceID,
                                      prekeyId: dto.preKey.id, prekey: PublicKey(dto.preKey.key),
                                      signedPrekeyId: dto.signedPreKey.id, signedPrekey: PublicKey(dto.signedPreKey.key),
                                      signedPrekeySignature: dto.signedPreKey.signature, identity: IdentityKey(bytes: dto.identityKey),
                                      kyberPrekeyId: dto.kyberPreKey.id, kyberPrekey: KEMPublicKey(dto.kyberPreKey.key), kyberPrekeySignature: dto.kyberPreKey.signature)
        try transaction {
            try processPreKeyBundle(bundle, for: address, ourAddress: ProtocolAddress(name: local.0.rawValue, deviceId: 1), sessionStore: store, identityStore: store, context: NullContext())
        }
        #else
        throw GhostError.cryptoUnavailable
        #endif
    }

    func hasSession(with id: GhostID) throws -> Bool {
        #if canImport(LibSignalClient)
        guard let store else { return false }
        return try store.loadSession(for: ProtocolAddress(name: id.rawValue, deviceId: 1), context: NullContext())?.hasCurrentState ?? false
        #else
        return false
        #endif
    }

    /// Returns the binary wire frame for the relay. The plaintext is padded to a fixed bucket before encryption.
    func encrypt(_ payload: PrivatePayload) throws -> Data {
        #if canImport(LibSignalClient)
        guard let store, let local = try loadIdentity(), payload.sender == local.0 else { throw GhostError.invalidPayload }
        try payload.validate(sender: payload.sender, recipient: payload.recipient)
        let plaintext = WirePadding.pad(try WireCodec.encoder().encode(payload))
        return try transaction {
            let message = try signalEncrypt(message: plaintext,
                                            for: ProtocolAddress(name: payload.recipient.rawValue, deviceId: 1),
                                            localAddress: ProtocolAddress(name: local.0.rawValue, deviceId: 1), sessionStore: store, identityStore: store, context: NullContext())
            guard message.messageType == .preKey || message.messageType == .whisper else { throw GhostError.invalidPayload }
            let wire = WireEnvelope(messageType: message.messageType.rawValue, ciphertext: message.serialize()).bytes
            guard wire.count <= Limits.maxWireBytes else { throw GhostError.tooLarge }
            return wire
        }
        #else
        throw GhostError.cryptoUnavailable
        #endif
    }

    /// expectedKey is the contact's pinned identity key. It is nil only for the first message on a one-time
    /// invitation queue; then only a PreKey message carrying a hello payload is accepted, and the sender's
    /// identity comes from that authenticated message.
    func decrypt(_ wire: Data, expectedKey: Data?) throws -> (payload: PrivatePayload, senderKey: Data) {
        #if canImport(LibSignalClient)
        guard let store, let local = try loadIdentity() else { throw GhostError.cryptoUnavailable }
        let envelope = try WireEnvelope(bytes: wire)
        let localAddress = try ProtocolAddress(name: local.0.rawValue, deviceId: 1)
        return try transaction {
            let senderKey: Data
            let bytes: Data
            if envelope.messageType == CiphertextMessage.MessageType.preKey.rawValue {
                let message = try PreKeySignalMessage(bytes: envelope.ciphertext)
                senderKey = message.identityKey.serialize()
                if let expectedKey, senderKey != expectedKey { throw GhostError.keyChanged }
                let sender = GhostID(identityKey: senderKey)
                guard sender != local.0 else { throw GhostError.invalidPayload }
                let address = try ProtocolAddress(name: sender.rawValue, deviceId: 1)
                bytes = try signalDecryptPreKey(message: message, from: address, localAddress: localAddress,
                                                sessionStore: store, identityStore: store, preKeyStore: store, signedPreKeyStore: store, kyberPreKeyStore: store, context: NullContext())
            } else if envelope.messageType == CiphertextMessage.MessageType.whisper.rawValue, let expectedKey {
                senderKey = expectedKey
                let address = try ProtocolAddress(name: GhostID(identityKey: expectedKey).rawValue, deviceId: 1)
                _ = try store.saveIdentity(try IdentityKey(bytes: expectedKey), for: address, context: NullContext())
                bytes = try signalDecrypt(message: SignalMessage(bytes: envelope.ciphertext), from: address, to: localAddress,
                                          sessionStore: store, identityStore: store, context: NullContext())
            } else { throw GhostError.invalidPayload }
            let payload = try WireCodec.decoder().decode(PrivatePayload.self, from: WirePadding.unpad(bytes))
            try payload.validate(sender: GhostID(identityKey: senderKey), recipient: local.0)
            if expectedKey == nil, payload.kind != .hello { throw GhostError.invalidPayload }
            return (payload, senderKey)
        }
        #else
        throw GhostError.cryptoUnavailable
        #endif
    }

    func safetyNumber(remoteID: GhostID, remoteKey: Data) throws -> String {
        #if canImport(LibSignalClient)
        guard let local = try loadIdentity(), GhostID(identityKey: remoteKey) == remoteID else { throw GhostError.keyChanged }
        return try NumericFingerprintGenerator(iterations: 5200).create(version: 2,
            localIdentifier: Data(local.0.rawValue.utf8), localKey: PublicKey(local.1),
            remoteIdentifier: Data(remoteID.rawValue.utf8), remoteKey: PublicKey(remoteKey)).displayable.formatted
        #else
        throw GhostError.cryptoUnavailable
        #endif
    }

    /// Drops the ratchet and pinned key of a removed contact.
    func forget(_ id: GhostID) throws {
        #if canImport(LibSignalClient)
        guard let store else { return }
        try transaction { store.forget(name: id.rawValue) }
        #endif
    }

    func deleteIdentity() throws {
        try vault?.delete("signal-state")
        #if canImport(LibSignalClient)
        store = nil
        #endif
    }

    /// Test hook: counts of stored key material, never key bytes.
    func keyMaterialCounts() -> (preKeys: Int, kyberPreKeys: Int, sessions: Int) {
        #if canImport(LibSignalClient)
        guard let store else { return (0, 0, 0) }
        return (store.state.preKeys.count, store.state.kyberPreKeys.count, store.state.sessions.count)
        #else
        return (0, 0, 0)
        #endif
    }

    #if canImport(LibSignalClient)
    private func commit() throws {
        guard let store else { return }
        try vault?.save(WireCodec.encoder().encode(store.state), account: "signal-state")
    }
    private func transaction<T>(_ body: () throws -> T) throws -> T {
        guard let store else { throw GhostError.cryptoUnavailable }
        let previous = store.state
        do { let result = try body(); try commit(); return result }
        catch { store.state = previous; throw error }
    }
    #endif
}
