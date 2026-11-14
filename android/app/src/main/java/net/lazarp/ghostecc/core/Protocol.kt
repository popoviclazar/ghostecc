package net.lazarp.ghostecc.core

import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import java.net.URI
import java.net.URISyntaxException
import java.nio.ByteBuffer
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** https://host[:port] in lower case, no path, query, fragment or credentials. Mirrors the server and iOS. */
object RelayOrigin {
    fun normalize(input: String): String {
        val uri = try { URI(input.trim()) } catch (e: URISyntaxException) { throw GhostError.InvalidURL }
        if (uri.scheme?.lowercase() != "https") throw GhostError.InvalidURL
        val host = uri.host?.lowercase() ?: throw GhostError.InvalidURL
        if (host.isEmpty() || host.contains(":")) throw GhostError.InvalidURL
        if (uri.rawUserInfo != null || uri.rawQuery != null || uri.rawFragment != null) throw GhostError.InvalidURL
        val path = uri.rawPath ?: ""
        if (path.isNotEmpty() && path != "/") throw GhostError.InvalidURL
        val port = uri.port
        if (port != -1 && port != 443) {
            if (port !in 1..65_535) throw GhostError.InvalidURL
            return "https://$host:$port"
        }
        return "https://$host"
    }
}

object RelayQueueID {
    private val QUEUE = Regex("^[A-Za-z0-9_-]{32}$")
    private val MESSAGE = Regex("^[A-Za-z0-9_-]{22}$")
    fun isValid(value: String) = QUEUE.matches(value)
    fun isValidMessage(value: String) = MESSAGE.matches(value)
}

/** Canonical request signature, see docs/RELAY-PROTOCOL.md. Byte-identical to server/src/relay.js and iOS. */
object RelaySigning {
    const val DOMAIN = "GHOST-RELAY-v1"
    fun digest(data: ByteArray): String = sha256(data).hexLower()
    fun message(origin: String, op: String, queueID: String, timestamp: Long, nonce: String, digest: String): ByteArray =
        listOf(DOMAIN, origin, op, queueID, timestamp.toString(), nonce, digest).joinToString("\n").toByteArray(Charsets.UTF_8)
}

/** Fixed-size buckets so the ciphertext length does not reveal the message length. */
object WirePadding {
    fun bucket(length: Int): Int {
        val framed = length + 4
        for (size in intArrayOf(1_024, 4_096, 16_384, 65_536)) if (framed <= size) return size
        val step = 262_144
        return (framed + step - 1) / step * step
    }
    fun pad(data: ByteArray): ByteArray {
        val out = ByteBuffer.allocate(bucket(data.size))
        out.putInt(data.size)
        out.put(data)
        return out.array()
    }
    fun unpad(data: ByteArray): ByteArray {
        if (data.size < 4) throw GhostError.InvalidPayload
        val length = ByteBuffer.wrap(data, 0, 4).int
        if (length < 0 || length > data.size - 4) throw GhostError.InvalidPayload
        return data.copyOfRange(4, 4 + length)
    }
}

/** Binary frame stored on the relay: version 2, libsignal message type (2 whisper, 3 prekey), ciphertext. */
class WireEnvelope(val messageType: Int, val ciphertext: ByteArray) {
    val bytes: ByteArray get() = byteArrayOf(VERSION.toByte(), messageType.toByte()) + ciphertext
    companion object {
        const val VERSION = 2
        fun parse(bytes: ByteArray): WireEnvelope {
            if (bytes.size <= 2 || bytes.size > Limits.maxWireBytes || bytes[0].toInt() != VERSION) throw GhostError.InvalidPayload
            return WireEnvelope(bytes[1].toInt() and 0xFF, bytes.copyOfRange(2, bytes.size))
        }
    }
}

// MARK: Key bundle (travels only inside an invitation, encrypted with the link key)

@Serializable
data class PublicPreKey(val id: Long, @Serializable(with = Base64Bytes::class) val key: ByteArray)

@Serializable
data class PublicSignedPreKey(
    val id: Long,
    @Serializable(with = Base64Bytes::class) val key: ByteArray,
    @Serializable(with = Base64Bytes::class) val signature: ByteArray,
)

@Serializable
data class KeyBundleDTO(
    val id: GhostID,
    val registrationID: Long,
    val deviceID: Long,
    @Serializable(with = Base64Bytes::class) val identityKey: ByteArray,
    val preKey: PublicPreKey,
    val signedPreKey: PublicSignedPreKey,
    val kyberPreKey: PublicSignedPreKey,
)

/** ghost-ecc://invite/<base64url JSON {k, q, s, v, x}>: inviter identity key, queue, relay origin, link key. */
@Serializable
data class InviteLink(
    @Serializable(with = Base64Bytes::class) val k: ByteArray,
    val q: String,
    val s: String,
    val v: Int,
    @Serializable(with = Base64Bytes::class) val x: ByteArray,
) {
    val ghostID: GhostID get() = GhostID.fromIdentityKey(k)
    fun string(): String = PREFIX + Base64Url.encode(WireJson.encodeToString(this).toByteArray(Charsets.UTF_8))

    companion object {
        const val PREFIX = "ghost-ecc://invite/"
        fun parse(input: String): InviteLink {
            val value = input.trim()
            if (value.length >= 2048 || !value.startsWith(PREFIX)) throw GhostError.InvalidInvite
            val bytes = Base64Url.decode(value.removePrefix(PREFIX)) ?: throw GhostError.InvalidInvite
            val link = try { WireJson.decodeFromString<InviteLink>(bytes.toString(Charsets.UTF_8)) } catch (e: Exception) { throw GhostError.InvalidInvite }
            val origin = try { RelayOrigin.normalize(link.s) } catch (e: GhostError) { null }
            if (link.v != 1 || link.k.size != 33 || link.x.size != 32 || !RelayQueueID.isValid(link.q) || origin != link.s) throw GhostError.InvalidInvite
            return link
        }
    }
}

/** AES-GCM sealed key bundle; combined form nonce(12) + ciphertext + tag(16), exactly like CryptoKit. */
object InviteCrypto {
    fun associatedData(identityKey: ByteArray): ByteArray =
        ("GHOST-INVITE-v1|" + Base64.getEncoder().encodeToString(identityKey)).toByteArray(Charsets.UTF_8)

    fun seal(bundle: KeyBundleDTO, key: ByteArray): ByteArray {
        val nonce = SecureRandomBytes.bytes(12)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(associatedData(bundle.identityKey))
        return nonce + cipher.doFinal(WireJson.encodeToString(bundle).toByteArray(Charsets.UTF_8))
    }

    fun open(blob: ByteArray, link: InviteLink): KeyBundleDTO {
        if (blob.size > 16_384 || blob.size < 12 + 16) throw GhostError.InvalidInvite
        val plaintext = try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(link.x, "AES"), GCMParameterSpec(128, blob.copyOfRange(0, 12)))
            cipher.updateAAD(associatedData(link.k))
            cipher.doFinal(blob.copyOfRange(12, blob.size))
        } catch (e: Exception) { throw GhostError.InvalidInvite }
        val bundle = try { WireJson.decodeFromString<KeyBundleDTO>(plaintext.toString(Charsets.UTF_8)) } catch (e: Exception) { throw GhostError.InvalidInvite }
        if (!bundle.identityKey.contentEquals(link.k) || bundle.id != link.ghostID || bundle.deviceID != 1L) throw GhostError.KeyChanged
        return bundle
    }
}

/** QR form of the 60-digit safety number. Scanning the other phone's code and matching proves nobody is in between. */
object SafetyCode {
    const val PREFIX = "ghost-ecc://verify/"
    fun link(number: String) = PREFIX + number.filter { it.isDigit() }
    fun matches(scanned: String, number: String): Boolean {
        val digits = number.filter { it.isDigit() }
        return digits.length == 60 && scanned == link(number)
    }
}

/** Voice messages are 16 kHz mono 16-bit WAV, as on iOS. */
object WAV {
    const val SAMPLE_RATE = 16_000
    const val HEADER_SIZE = 44
    fun isValid(data: ByteArray): Boolean =
        data.size > HEADER_SIZE && String(data, 0, 4, Charsets.US_ASCII) == "RIFF" && String(data, 8, 4, Charsets.US_ASCII) == "WAVE"

    fun wrap(pcm: ByteArray, sampleRate: Int = SAMPLE_RATE): ByteArray {
        val out = ByteBuffer.allocate(HEADER_SIZE + pcm.size).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        out.put("RIFF".toByteArray()); out.putInt(36 + pcm.size); out.put("WAVE".toByteArray())
        out.put("fmt ".toByteArray()); out.putInt(16); out.putShort(1); out.putShort(1); out.putInt(sampleRate)
        out.putInt(sampleRate * 2); out.putShort(2); out.putShort(16)
        out.put("data".toByteArray()); out.putInt(pcm.size); out.put(pcm)
        return out.array()
    }

    fun durationSeconds(data: ByteArray): Double {
        if (!isValid(data)) return 0.0
        val byteRate = ByteBuffer.wrap(data, 28, 4).order(java.nio.ByteOrder.LITTLE_ENDIAN).int
        return if (byteRate > 0) (data.size - HEADER_SIZE).toDouble() / byteRate else 0.0
    }
}
