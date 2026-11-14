package net.lazarp.ghostecc.security

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import net.lazarp.ghostecc.core.GhostError
import net.lazarp.ghostecc.core.GhostID
import net.lazarp.ghostecc.core.KeyBundleDTO
import net.lazarp.ghostecc.core.Limits
import net.lazarp.ghostecc.core.PayloadKind
import net.lazarp.ghostecc.core.PrivatePayload
import net.lazarp.ghostecc.core.PublicPreKey
import net.lazarp.ghostecc.core.PublicSignedPreKey
import net.lazarp.ghostecc.core.WireEnvelope
import net.lazarp.ghostecc.core.WireJson
import net.lazarp.ghostecc.core.WirePadding
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.UntrustedIdentityException
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.fingerprint.NumericFingerprintGenerator
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.kem.KEMPublicKey
import org.signal.libsignal.protocol.message.CiphertextMessage
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SessionRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore
import java.security.SecureRandom
import java.util.Base64

/** Complete protocol state as one value, like SignalSnapshot on iOS. Records are libsignal's own serialization. */
@Serializable
data class SignalSnapshot(
    val identity: String,
    val registrationID: Int,
    val identities: Map<String, String> = emptyMap(),
    val sessions: Map<String, String> = emptyMap(),
    val preKeys: Map<String, String> = emptyMap(),
    val signedPreKeys: Map<String, String> = emptyMap(),
    val kyberPreKeys: Map<String, String> = emptyMap(),
    val issuedAt: Map<String, Long> = emptyMap(),
)

data class Decrypted(val payload: PrivatePayload, val senderKey: ByteArray)

/**
 * The only file that talks to libsignal. Every operation builds a fresh in-memory store from the saved
 * snapshot, runs, and replaces the snapshot only if everything succeeded, so a failed decryption or an invalid
 * payload never advances the ratchet. Addresses are Ghost IDs with device 1, exactly as on iOS.
 */
class SignalEngine(private val vault: Vault?) {
    private val mutex = Mutex()
    private var snapshot: SignalSnapshot? = null
    private val random = SecureRandom()

    /** Same identity, separate RAM-only state: Ghost Lab never touches the real ratchet. */
    suspend fun localTestClone(): SignalEngine = mutex.withLock {
        val snap = snapshot ?: throw GhostError.CryptoUnavailable
        SignalEngine(null).also { it.snapshot = SignalSnapshot(snap.identity, snap.registrationID) }
    }

    suspend fun loadIdentity(create: Boolean = false): Pair<GhostID, ByteArray>? = mutex.withLock { loadLocked(create) }

    /** A fresh one-time bundle for exactly one invitation. Its private halves stay in the saved snapshot. */
    suspend fun invitationBundle(): KeyBundleDTO = mutex.withLock {
        val (me, key) = loadLocked(false) ?: throw GhostError.CryptoUnavailable
        var snap = pruned(snapshot!!)
        if (snap.preKeys.size >= MAX_UNUSED_BUNDLES || snap.issuedAt.size >= 256) throw GhostError.Limit
        // Positive 31-bit IDs: libsignal's Java API takes key IDs as a signed int (iOS uses the same range).
        var id: Int
        do { id = random.nextInt(0x7FFF_FFFF) + 1 } while (snap.issuedAt.containsKey(id.toString()))
        val identity = IdentityKeyPair(b64d(snap.identity))
        val pre = ECKeyPair.generate()
        val signed = ECKeyPair.generate()
        val kyber = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
        val signedSignature = identity.privateKey.calculateSignature(signed.publicKey.serialize())
        val kyberSignature = identity.privateKey.calculateSignature(kyber.publicKey.serialize())
        val now = System.currentTimeMillis()
        val name = id.toString()
        snap = snap.copy(
            preKeys = snap.preKeys + (name to b64(PreKeyRecord(id, pre).serialize())),
            signedPreKeys = snap.signedPreKeys + (name to b64(SignedPreKeyRecord(id, now, signed, signedSignature).serialize())),
            kyberPreKeys = snap.kyberPreKeys + (name to b64(KyberPreKeyRecord(id, now, kyber, kyberSignature).serialize())),
            issuedAt = snap.issuedAt + (name to now),
        )
        commit(snap)
        KeyBundleDTO(
            id = me, registrationID = snap.registrationID.toLong(), deviceID = 1, identityKey = key,
            preKey = PublicPreKey(id.toLong(), pre.publicKey.serialize()),
            signedPreKey = PublicSignedPreKey(id.toLong(), signed.publicKey.serialize(), signedSignature),
            kyberPreKey = PublicSignedPreKey(id.toLong(), kyber.publicKey.serialize(), kyberSignature),
        )
    }

    /** Removes the private keys of a cancelled or expired invitation. */
    suspend fun discardBundle(id: Long) = mutex.withLock {
        val snap = snapshot ?: return@withLock
        commit(withoutBundle(snap, id.toString()))
    }

    suspend fun prepareSession(dto: KeyBundleDTO) = mutex.withLock {
        val (me, _) = loadLocked(false) ?: throw GhostError.CryptoUnavailable
        if (dto.deviceID != 1L || GhostID.fromIdentityKey(dto.identityKey) != dto.id || dto.id == me) throw GhostError.KeyChanged
        val ids = listOf(dto.preKey.id, dto.signedPreKey.id, dto.kyberPreKey.id)
        // Invitations from iOS 1.0 could carry IDs above 2^31, which libsignal's Java API cannot take.
        if (ids.any { it !in 1..0x7FFF_FFFFL } || dto.registrationID !in 1..0x7FFF_FFFFL) throw GhostError.InvalidInvite
        val snap = snapshot!!
        // Do not reset an existing ratchet when the same bundle is processed again.
        if (snap.sessions.containsKey(dto.id.rawValue)) return@withLock
        guard {
            val store = open(snap)
            val bundle = PreKeyBundle(
                dto.registrationID.toInt(), 1,
                dto.preKey.id.toInt(), ECPublicKey(dto.preKey.key),
                dto.signedPreKey.id.toInt(), ECPublicKey(dto.signedPreKey.key), dto.signedPreKey.signature,
                IdentityKey(dto.identityKey),
                dto.kyberPreKey.id.toInt(), KEMPublicKey(dto.kyberPreKey.key), dto.kyberPreKey.signature,
            )
            SessionBuilder(store, address(dto.id.rawValue)).process(bundle)
            commit(extract(store, snap, extra = dto.id.rawValue))
        }
    }

    suspend fun hasSession(id: GhostID): Boolean = mutex.withLock { snapshot?.sessions?.containsKey(id.rawValue) == true }

    /** The binary wire frame for the relay. The plaintext is padded to a fixed bucket before encryption. */
    suspend fun encrypt(payload: PrivatePayload): ByteArray = mutex.withLock {
        val (me, _) = loadLocked(false) ?: throw GhostError.CryptoUnavailable
        if (payload.sender != me) throw GhostError.InvalidPayload
        payload.validate(payload.sender, payload.recipient)
        val plaintext = WirePadding.pad(WireJson.encodeToString(payload).toByteArray(Charsets.UTF_8))
        val snap = snapshot!!
        guard {
            val store = open(snap)
            val message = SessionCipher(store, address(payload.recipient.rawValue)).encrypt(plaintext)
            val type = message.type
            if (type != CiphertextMessage.PREKEY_TYPE && type != CiphertextMessage.WHISPER_TYPE) throw GhostError.InvalidPayload
            val wire = WireEnvelope(type, message.serialize()).bytes
            if (wire.size > Limits.maxWireBytes) throw GhostError.TooLarge
            commit(extract(store, snap, extra = payload.recipient.rawValue))
            wire
        }
    }

    /**
     * expectedKey is the contact's pinned identity key. It is null only for the first message on a one-time
     * invitation queue; then only a PreKey message carrying hello is accepted, and the sender's identity comes
     * from that authenticated message.
     */
    suspend fun decrypt(wire: ByteArray, expectedKey: ByteArray?): Decrypted = mutex.withLock {
        val (me, _) = loadLocked(false) ?: throw GhostError.CryptoUnavailable
        val envelope = WireEnvelope.parse(wire)
        val snap = snapshot!!
        guard {
            val store = open(snap)
            val senderKey: ByteArray
            val plaintext: ByteArray
            when {
                envelope.messageType == CiphertextMessage.PREKEY_TYPE -> {
                    val message = PreKeySignalMessage(envelope.ciphertext)
                    senderKey = message.identityKey.serialize()
                    if (expectedKey != null && !senderKey.contentEquals(expectedKey)) throw GhostError.KeyChanged
                    val sender = GhostID.fromIdentityKey(senderKey)
                    if (sender == me) throw GhostError.InvalidPayload
                    plaintext = SessionCipher(store, address(sender.rawValue)).decrypt(message)
                }
                envelope.messageType == CiphertextMessage.WHISPER_TYPE && expectedKey != null -> {
                    senderKey = expectedKey
                    val addr = address(GhostID.fromIdentityKey(expectedKey).rawValue)
                    store.saveIdentity(addr, IdentityKey(expectedKey))
                    plaintext = SessionCipher(store, addr).decrypt(SignalMessage(envelope.ciphertext))
                }
                else -> throw GhostError.InvalidPayload
            }
            val payload = try {
                WireJson.decodeFromString<PrivatePayload>(WirePadding.unpad(plaintext).toString(Charsets.UTF_8))
            } catch (e: GhostError) { throw e } catch (e: Exception) { throw GhostError.InvalidPayload }
            payload.validate(GhostID.fromIdentityKey(senderKey), me)
            if (expectedKey == null && payload.kind != PayloadKind.hello) throw GhostError.InvalidPayload
            var next = extract(store, snap, extra = GhostID.fromIdentityKey(senderKey).rawValue)
            // libsignal removes the one-time EC prekey it used. Every Ghost Talk Kyber prekey belongs to exactly
            // one invitation, so the Kyber key of that bundle goes too: one-time, deleted after use.
            val usedBundles = snap.preKeys.keys - next.preKeys.keys
            if (usedBundles.isNotEmpty()) next = next.copy(kyberPreKeys = next.kyberPreKeys - usedBundles)
            commit(next)
            Decrypted(payload, senderKey)
        }
    }

    /** 60 digits, identical on both phones and on iOS: version 2, 5200 iterations, Ghost IDs as identifiers. */
    suspend fun safetyNumber(remoteID: GhostID, remoteKey: ByteArray): String = mutex.withLock {
        val (me, key) = loadLocked(false) ?: throw GhostError.CryptoUnavailable
        if (GhostID.fromIdentityKey(remoteKey) != remoteID) throw GhostError.KeyChanged
        NumericFingerprintGenerator(5200).createFor(
            2,
            me.rawValue.toByteArray(Charsets.UTF_8), IdentityKey(key),
            remoteID.rawValue.toByteArray(Charsets.UTF_8), IdentityKey(remoteKey),
        ).displayableFingerprint.displayText
    }

    /** Drops the ratchet and pinned key of a removed contact. */
    suspend fun forget(id: GhostID) = mutex.withLock {
        val snap = snapshot ?: return@withLock
        commit(snap.copy(sessions = snap.sessions - id.rawValue, identities = snap.identities - id.rawValue))
    }

    suspend fun deleteIdentity() = mutex.withLock {
        vault?.delete(ACCOUNT)
        snapshot = null
    }

    /** Test hook: counts of stored key material, never key bytes. */
    suspend fun keyMaterialCounts(): Triple<Int, Int, Int> = mutex.withLock {
        val snap = snapshot ?: return@withLock Triple(0, 0, 0)
        Triple(snap.preKeys.size, snap.kyberPreKeys.size, snap.sessions.size)
    }

    // MARK: Internals

    private fun loadLocked(create: Boolean): Pair<GhostID, ByteArray>? {
        if (snapshot == null) {
            val data = vault?.load(ACCOUNT)
            if (data != null) {
                snapshot = WireJson.decodeFromString<SignalSnapshot>(data.toString(Charsets.UTF_8))
            } else if (create) {
                val pair = IdentityKeyPair.generate()
                val created = SignalSnapshot(b64(pair.serialize()), random.nextInt(0x3FFF) + 1)
                snapshot = created
                try { commit(created) } catch (e: Exception) { snapshot = null; throw e }
            }
        }
        val snap = snapshot ?: return null
        val key = IdentityKeyPair(b64d(snap.identity)).publicKey.serialize()
        return GhostID.fromIdentityKey(key) to key
    }

    private fun commit(next: SignalSnapshot) {
        vault?.save(WireJson.encodeToString(next).toByteArray(Charsets.UTF_8), ACCOUNT)
        snapshot = next
    }

    private fun open(snap: SignalSnapshot): InMemorySignalProtocolStore {
        val store = InMemorySignalProtocolStore(IdentityKeyPair(b64d(snap.identity)), snap.registrationID)
        snap.identities.forEach { (name, key) -> store.saveIdentity(address(name), IdentityKey(b64d(key))) }
        snap.sessions.forEach { (name, record) -> store.storeSession(address(name), SessionRecord(b64d(record))) }
        snap.preKeys.forEach { (id, record) -> store.storePreKey(id.toInt(), PreKeyRecord(b64d(record))) }
        snap.signedPreKeys.forEach { (id, record) -> store.storeSignedPreKey(id.toInt(), SignedPreKeyRecord(b64d(record))) }
        snap.kyberPreKeys.forEach { (id, record) -> store.storeKyberPreKey(id.toInt(), KyberPreKeyRecord(b64d(record))) }
        return store
    }

    /** Reads back everything the snapshot tracks, plus the address the operation touched. */
    private fun extract(store: InMemorySignalProtocolStore, base: SignalSnapshot, extra: String): SignalSnapshot {
        val names = base.sessions.keys + base.identities.keys + extra
        if (names.size > Limits.maxContacts + Limits.maxInvites) throw GhostError.Limit
        val identities = mutableMapOf<String, String>()
        val sessions = mutableMapOf<String, String>()
        for (name in names) {
            val addr = address(name)
            store.getIdentity(addr)?.let { identities[name] = b64(it.serialize()) }
            if (store.containsSession(addr)) sessions[name] = b64(store.loadSession(addr).serialize())
        }
        val preKeys = mutableMapOf<String, String>()
        val signed = mutableMapOf<String, String>()
        val kyber = mutableMapOf<String, String>()
        for (name in base.issuedAt.keys) {
            val id = name.toInt()
            if (store.containsPreKey(id)) preKeys[name] = b64(store.loadPreKey(id).serialize())
            if (store.containsSignedPreKey(id)) signed[name] = b64(store.loadSignedPreKey(id).serialize())
            if (store.containsKyberPreKey(id)) kyber[name] = b64(store.loadKyberPreKey(id).serialize())
        }
        return base.copy(identities = identities, sessions = sessions, preKeys = preKeys, signedPreKeys = signed, kyberPreKeys = kyber)
    }

    private fun withoutBundle(snap: SignalSnapshot, id: String) = snap.copy(
        preKeys = snap.preKeys - id, signedPreKeys = snap.signedPreKeys - id, kyberPreKeys = snap.kyberPreKeys - id, issuedAt = snap.issuedAt - id,
    )

    /** Bundles are kept 8 days (an invitation is valid for 7). */
    private fun pruned(snap: SignalSnapshot): SignalSnapshot {
        val cutoff = System.currentTimeMillis() - BUNDLE_RETENTION_MS
        return snap.issuedAt.filterValues { it < cutoff }.keys.fold(snap) { acc, id -> withoutBundle(acc, id) }
    }

    /** libsignal errors become Ghost errors; nothing is committed when anything throws. */
    private inline fun <T> guard(body: () -> T): T = try {
        body()
    } catch (e: GhostError) {
        throw e
    } catch (e: UntrustedIdentityException) {
        throw GhostError.KeyChanged
    } catch (e: Exception) {
        throw GhostError.InvalidPayload
    }

    private fun address(name: String) = SignalProtocolAddress(name, 1)
    private fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)
    private fun b64d(text: String): ByteArray = Base64.getDecoder().decode(text)

    companion object {
        private const val ACCOUNT = "signal-state"
        private const val MAX_UNUSED_BUNDLES = 32
        private const val BUNDLE_RETENTION_MS = 8L * 86_400_000
    }
}
