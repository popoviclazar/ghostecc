package net.lazarp.ghostecc.core

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.security.MessageDigest
import java.security.SecureRandom

/** Same errors and English texts as the iOS app. */
sealed class GhostError(message: String) : Exception(message) {
    data object InvalidID : GhostError("A Ghost ID must contain GHOST- and 64 hexadecimal characters.")
    data object OwnID : GhostError("This is your own invitation.")
    data object DuplicateContact : GhostError("This contact already exists.")
    data object Blocked : GhostError("The contact is blocked.")
    data object Unavailable : GhostError("The server is unreachable. Check your internet connection and try again.")
    data object Unverified : GhostError("Compare the safety number with your contact first.")
    data object KeyChanged : GhostError("The security key does not match this contact. The action was stopped.")
    data object InvalidPayload : GhostError("The message is not valid.")
    data object Expired : GhostError("The message has expired.")
    data object TooLarge : GhostError("The content is too large.")
    data object CryptoUnavailable : GhostError("Encryption is unavailable. Nothing is sent without encryption.")
    data object Storage : GhostError("Protected storage is unavailable. Unlock the device and try again.")
    data object Limit : GhostError("This version's limit has been reached.")
    class Server(val status: Int) : GhostError("The server rejected the request ($status).")
    data object InvalidURL : GhostError("Enter the server's HTTPS address without a path, credentials or parameters.")
    data object UnknownContact : GhostError("The contact does not exist.")
    data object ClockSkew : GhostError("The server and device times differ. Turn on automatic time on your phone.")
    data object InvalidInvite : GhostError("The invitation is not valid. Check that it was copied completely.")
    data object InvitationUsed : GhostError("The invitation was already used, cancelled or has expired. Ask for a new one.")
    data object QueueGone : GhostError("The mailbox no longer exists on the server.")
    data object Unauthorized : GhostError("The server rejected the request signature.")
    data object RateLimited : GhostError("The server is busy or a limit was reached. Try again a little later.")
    data object Disconnected : GhostError("The connection with this contact was closed. Reconnect with a new invitation.")
    data object GroupNotConnected : GhostError("Group members are not connected yet. Sending will work as soon as they are.")
}

object Limits {
    const val maxWireBytes = 6_000_000
    const val maxTextBytes = 16_384
    const val maxPhotoBytes = 4_000_000
    const val maxVoiceBytes = 3_000_000
    const val maxFileBytes = 4_000_000
    const val maxContacts = 200
    const val maxInvites = 20
    const val maxGroups = 30
    const val maxMessagesPerContact = 500
    const val maxPhotoMemory = 32_000_000
}

object SecureRandomBytes {
    private val random = SecureRandom()
    fun bytes(count: Int): ByteArray = ByteArray(count).also { random.nextBytes(it) }
}

fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

/** GHOST- + SHA-256 of the 33-byte identity key, upper-case hex. Identical to iOS. */
@Serializable(with = GhostIDSerializer::class)
data class GhostID(val rawValue: String) : Comparable<GhostID> {
    init { require(PATTERN.matches(rawValue)) { "invalid Ghost ID" } }
    override fun toString() = rawValue
    override fun compareTo(other: GhostID) = rawValue.compareTo(other.rawValue)
    val short: String get() = rawValue.take(14) + "…" + rawValue.takeLast(6)

    companion object {
        private val PATTERN = Regex("^GHOST-[0-9A-F]{64}$")
        fun fromIdentityKey(key: ByteArray) = GhostID("GHOST-" + sha256(key).hexUpper())
        fun parse(input: String): GhostID {
            val value = input.trim().uppercase()
            if (!PATTERN.matches(value)) throw GhostError.InvalidID
            return GhostID(value)
        }
    }
}

object GhostIDSerializer : KSerializer<GhostID> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("GhostID", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: GhostID) = encoder.encodeString(value.rawValue)
    override fun deserialize(decoder: Decoder): GhostID = GhostID.parse(decoder.decodeString())
}

enum class ConnectionState { connecting, connected, disconnected }

/** A queue where this device receives. The recipient key never leaves protected storage. */
@Serializable
data class InboundQueue(
    val server: String,
    val recipientID: String,
    val senderID: String,
    @Serializable(with = Base64Bytes::class) val recipientKey: ByteArray,
) {
    override fun equals(other: Any?) = other is InboundQueue && other.recipientID == recipientID && other.server == server
    override fun hashCode() = recipientID.hashCode()
}

/** A queue owned by the contact, where this device sends. The sender key secures it on first use. */
@Serializable
data class OutboundQueue(
    val server: String,
    val senderID: String,
    @Serializable(with = Base64Bytes::class) val senderKey: ByteArray,
    val secured: Boolean,
) {
    override fun equals(other: Any?) = other is OutboundQueue && other.senderID == senderID && other.server == server && other.secured == secured
    override fun hashCode() = senderID.hashCode()
}

@Serializable
data class Contact(
    val ghostID: GhostID,
    val name: String,
    @Serializable(with = Base64Bytes::class) val identityKey: ByteArray,
    val verified: Boolean = false,
    val blocked: Boolean = false,
    val isDemo: Boolean = false,
    val state: ConnectionState = ConnectionState.connected,
    val inbound: InboundQueue? = null,
    val outbound: OutboundQueue? = null,
    /** Set for connections made automatically between members of these groups ("introduced"). */
    val introducedIn: List<String>? = null,
) {
    val id: String get() = ghostID.rawValue
    val title: String get() = name.ifEmpty { ghostID.short }
    val isIntroduced: Boolean get() = introducedIn != null
    override fun equals(other: Any?) = other is Contact && other.ghostID == ghostID && other.name == name && other.verified == verified &&
        other.blocked == blocked && other.state == state && other.inbound == inbound && other.outbound == outbound && other.introducedIn == introducedIn
    override fun hashCode() = ghostID.hashCode()
}

@Serializable
data class IntroductionTag(val groupID: String, val member: GhostID)

@Serializable
data class PendingInvite(
    @Serializable(with = UpperUUID::class) val id: java.util.UUID,
    val name: String,
    val inbound: InboundQueue,
    val link: String,
    val preKeyID: Long,
    @Serializable(with = EpochMillis::class) val createdAt: Long,
    val introduction: IntroductionTag? = null,
) {
    val title: String get() = name.ifEmpty { "Invitation" }
    val expiresAt: Long get() = createdAt + LIFETIME_MS
    fun isExpired(now: Long = System.currentTimeMillis()) = now >= expiresAt
    companion object { const val LIFETIME_MS = 7L * 86_400_000 }
}

@Serializable
data class ReplyAddress(val server: String, val senderID: String)

/** A file sent as content. The type is an Apple-style type identifier (e.g. com.adobe.pdf), as on iOS. */
@Serializable
data class FileAttachment(
    val name: String,
    val type: String,
    @Serializable(with = Base64Bytes::class) val data: ByteArray,
) {
    val isWellFormed: Boolean
        get() = data.isNotEmpty() && cleanName(name) == name && type.isNotEmpty() && type.length <= 128 && TYPE.matches(type)
    override fun equals(other: Any?) = other is FileAttachment && other.name == name && other.type == type && other.data.contentEquals(data)
    override fun hashCode() = name.hashCode()

    companion object {
        const val maxNameLength = 120
        private val TYPE = Regex("^[A-Za-z0-9.+-]+$")
        /** Same cleaning as iOS: no path separators or control characters, no leading dots, at most 120 characters. */
        fun cleanName(raw: String): String {
            val replaced = buildString {
                for (ch in raw) append(if (ch == '/' || ch == '\\' || ch == ':' || ch.isISOControl()) '_' else ch)
            }
            var name = replaced.trim()
            while (name.startsWith(".")) name = name.drop(1)
            if (name.codePointCount(0, name.length) > maxNameLength) name = name.substring(0, name.offsetByCodePoints(0, maxNameLength))
            return name.ifEmpty { "file" }
        }

        /** iOS expects type identifiers, never MIME types (a slash would be rejected). */
        fun typeIdentifier(mime: String?): String = when (mime?.lowercase()) {
            "application/pdf" -> "com.adobe.pdf"
            "image/jpeg" -> "public.jpeg"
            "image/png" -> "public.png"
            "image/heic" -> "public.heic"
            "text/plain" -> "public.plain-text"
            "text/csv" -> "public.comma-separated-values-text"
            "application/zip" -> "public.zip-archive"
            "audio/mpeg" -> "public.mp3"
            "video/mp4" -> "public.mpeg-4"
            "application/msword" -> "com.microsoft.word.doc"
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document" -> "org.openxmlformats.wordprocessingml.document"
            "application/vnd.ms-excel" -> "com.microsoft.excel.xls"
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" -> "org.openxmlformats.spreadsheetml.sheet"
            else -> "public.data"
        }

        fun mimeType(identifier: String): String = when (identifier) {
            "com.adobe.pdf" -> "application/pdf"
            "public.jpeg" -> "image/jpeg"
            "public.png" -> "image/png"
            "public.heic" -> "image/heic"
            "public.plain-text", "public.utf8-plain-text" -> "text/plain"
            "public.comma-separated-values-text" -> "text/csv"
            "public.zip-archive" -> "application/zip"
            "public.mp3" -> "audio/mpeg"
            "public.mpeg-4" -> "video/mp4"
            "com.microsoft.word.doc" -> "application/msword"
            "org.openxmlformats.wordprocessingml.document" -> "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            "com.microsoft.excel.xls" -> "application/vnd.ms-excel"
            "org.openxmlformats.spreadsheetml.sheet" -> "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            else -> "application/octet-stream"
        }
    }
}

// MARK: Groups

@Serializable
data class GroupMember(
    val ghostID: GhostID,
    val name: String,
    @Serializable(with = Base64Bytes::class) val identityKey: ByteArray,
) {
    override fun equals(other: Any?) = other is GroupMember && other.ghostID == ghostID && other.name == name && other.identityKey.contentEquals(identityKey)
    override fun hashCode() = ghostID.hashCode()
}

enum class GroupState { invited, joined }

@Serializable
data class GhostGroup(
    val id: String,
    val name: String,
    val admin: GhostID,
    val members: List<GroupMember>,
    val state: GroupState,
    @Serializable(with = EpochMillis::class) val createdAt: Long,
    val pendingIntros: Map<String, String>? = null,
    val isDemo: Boolean? = null,
) {
    val chatID: String get() = CHAT_PREFIX + id
    val title: String get() = name.ifEmpty { "Group" }
    fun member(id: GhostID): GroupMember? = members.firstOrNull { it.ghostID == id }

    companion object {
        const val maxMembers = 20
        const val CHAT_PREFIX = "group:"
        private val ID = Regex("^[A-Za-z0-9_-]{22}$")
        fun isValidID(id: String) = ID.matches(id)
        fun newID(): String = Base64Url.encode(SecureRandomBytes.bytes(16)).take(22)
    }
}

/** Group context of a payload: content carries only the id, control messages carry what they change. */
@Serializable
data class GroupInfo(
    val id: String,
    val name: String? = null,
    val admin: GhostID? = null,
    val members: List<GroupMember>? = null,
    val dissolved: Boolean? = null,
    val introFor: GhostID? = null,
    val link: String? = null,
) {
    val isReferenceOnly: Boolean
        get() = name == null && admin == null && members == null && dissolved == null && introFor == null && link == null
}

/** A chat a message can go to: a contact or a group. */
data class ChatTarget(val id: String, val title: String, val isGroup: Boolean)
