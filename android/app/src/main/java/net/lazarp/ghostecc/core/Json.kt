package net.lazarp.ghostecc.core

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import java.util.Base64
import java.util.UUID

/**
 * Same JSON as the iOS app (WireCodec): binary data as standard Base64 with padding, dates as
 * Unix milliseconds, UUIDs as upper-case strings, absent optionals omitted. iOS may write
 * milliseconds with a fraction, so dates are read as numbers of either kind.
 */
val WireJson = Json {
    ignoreUnknownKeys = true
    explicitNulls = false
    encodeDefaults = false
}

object Base64Bytes : KSerializer<ByteArray> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Base64Bytes", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: ByteArray) = encoder.encodeString(Base64.getEncoder().encodeToString(value))
    override fun deserialize(decoder: Decoder): ByteArray =
        try { Base64.getDecoder().decode(decoder.decodeString()) } catch (e: IllegalArgumentException) { throw GhostError.InvalidPayload }
}

/** Unix milliseconds. Encoded as an integer; decoded from an integer or a decimal number. */
object EpochMillis : KSerializer<Long> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("EpochMillis", PrimitiveKind.LONG)
    override fun serialize(encoder: Encoder, value: Long) = encoder.encodeLong(value)
    override fun deserialize(decoder: Decoder): Long {
        val json = decoder as? JsonDecoder ?: return decoder.decodeLong()
        val primitive: JsonPrimitive = json.decodeJsonElement().jsonPrimitive
        return primitive.content.toDoubleOrNull()?.let { kotlin.math.floor(it).toLong() } ?: throw GhostError.InvalidPayload
    }
}

object UpperUUID : KSerializer<UUID> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("UpperUUID", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: UUID) = encoder.encodeString(value.toString().uppercase())
    override fun deserialize(decoder: Decoder): UUID =
        try { UUID.fromString(decoder.decodeString()) } catch (e: IllegalArgumentException) { throw GhostError.InvalidPayload }
}

/** Base64URL without padding, as used in links, nonces and queue IDs. */
object Base64Url {
    fun encode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    fun decode(text: String): ByteArray? = try { Base64.getUrlDecoder().decode(text) } catch (e: IllegalArgumentException) { null }
}

fun ByteArray.hexLower(): String = joinToString("") { "%02x".format(it) }
fun ByteArray.hexUpper(): String = joinToString("") { "%02X".format(it) }
