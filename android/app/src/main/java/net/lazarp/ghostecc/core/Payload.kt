package net.lazarp.ghostecc.core

import kotlinx.serialization.Serializable
import java.util.UUID

@Suppress("EnumEntryName")
@Serializable
enum class PayloadKind { text, photo, hello, ready, voice, file, groupUpdate, groupLeave, groupIntro, reaction, retract }

/** The message a reply refers to; its preview travels with the reply. */
@Serializable
data class Quote(@Serializable(with = UpperUUID::class) val id: UUID, val sender: GhostID, val preview: String) {
    /** iOS limits the preview to 120 characters; on receipt only the byte bound is enforced (grapheme counts differ by platform). */
    val isWellFormed: Boolean get() = preview.toByteArray(Charsets.UTF_8).size <= 600
    companion object {
        const val maxPreviewCodePoints = 120
        fun previewOf(text: String): String =
            if (text.codePointCount(0, text.length) <= maxPreviewCodePoints) text else text.substring(0, text.offsetByCodePoints(0, maxPreviewCodePoints))
    }
}

/** What a content message carries. */
sealed class Content {
    data class Text(val value: String) : Content()
    class Photo(val data: ByteArray) : Content()
    class Voice(val data: ByteArray) : Content()
    class File(val attachment: FileAttachment) : Content()
}

/**
 * The JSON inside every Signal message, version 2. Field names, kinds and every validation rule match
 * PrivatePayload in the iOS app; a difference would make one platform reject the other's messages.
 */
@Serializable
data class PrivatePayload(
    val version: Int,
    val kind: PayloadKind,
    @Serializable(with = UpperUUID::class) val id: UUID,
    val sender: GhostID,
    val recipient: GhostID,
    @Serializable(with = EpochMillis::class) val sentAt: Long,
    @Serializable(with = EpochMillis::class) val expiresAt: Long,
    val text: String? = null,
    @Serializable(with = Base64Bytes::class) val photo: ByteArray? = null,
    @Serializable(with = Base64Bytes::class) val voice: ByteArray? = null,
    val file: FileAttachment? = null,
    val reply: ReplyAddress? = null,
    val group: GroupInfo? = null,
    val forwarded: Boolean? = null,
    val quote: Quote? = null,
    @Serializable(with = UpperUUID::class) val target: UUID? = null,
    val emoji: String? = null,
) {
    val content: Content?
        get() = when (kind) {
            PayloadKind.text -> text?.let { Content.Text(it) }
            PayloadKind.photo -> photo?.let { Content.Photo(it) }
            PayloadKind.voice -> voice?.let { Content.Voice(it) }
            PayloadKind.file -> file?.let { Content.File(it) }
            else -> null
        }

    fun validate(expectedSender: GhostID, expectedRecipient: GhostID, now: Long = System.currentTimeMillis()) {
        if (version != 2 || sender != expectedSender || recipient != expectedRecipient ||
            expiresAt <= sentAt || expiresAt - sentAt > MAX_LIFETIME_MS || sentAt - now > 120_000) throw GhostError.InvalidPayload
        // Exactly one kind of content per message, matching the declared kind.
        val present = listOf(text != null, photo != null, voice != null, file != null).count { it }
        group?.let { if (!GhostGroup.isValidID(it.id)) throw GhostError.InvalidPayload }
        val noSignal = target == null && emoji == null
        val plainContent = reply == null && (group?.isReferenceOnly ?: true) && noSignal && (quote?.isWellFormed ?: true)
        val control = present == 0 && reply == null && forwarded == null && quote == null && noSignal
        val signal = present == 0 && reply == null && forwarded == null && quote == null && target != null && (group?.isReferenceOnly ?: true)
        val ok = when (kind) {
            PayloadKind.text -> text != null && present == 1 && plainContent
            PayloadKind.photo -> photo != null && present == 1 && plainContent
            PayloadKind.voice -> voice != null && present == 1 && plainContent
            PayloadKind.file -> file != null && present == 1 && plainContent
            PayloadKind.reaction -> signal && emoji != null && emoji.toByteArray(Charsets.UTF_8).size <= 32
            PayloadKind.retract -> signal && emoji == null
            PayloadKind.hello -> {
                val reply = reply
                present == 0 && group == null && forwarded == null && quote == null && noSignal && reply != null && RelayQueueID.isValid(reply.senderID) &&
                    runCatching { RelayOrigin.normalize(reply.server) }.getOrNull() == reply.server
            }
            PayloadKind.ready -> control && group == null
            PayloadKind.groupUpdate -> control && group != null && group.introFor == null && group.link == null &&
                group.admin == sender && (group.dissolved == true || validMembers(group))
            PayloadKind.groupLeave -> control && group != null && group.isReferenceOnly
            PayloadKind.groupIntro -> control && group != null && group.introFor != null && group.link != null &&
                runCatching { InviteLink.parse(group.link ?: "") }.isSuccess &&
                group.name == null && group.admin == null && group.members == null && group.dissolved == null
        }
        if (!ok) throw GhostError.InvalidPayload
        if (expiresAt <= now) throw GhostError.Expired
        checkContent(text, photo, voice, file)
    }

    private fun validMembers(group: GroupInfo): Boolean {
        val name = group.name ?: return false
        val members = group.members ?: return false
        return name.length <= 80 && members.size in 2..GhostGroup.maxMembers &&
            members.map { it.ghostID }.toSet().size == members.size && members.any { it.ghostID == sender } &&
            members.all { it.name.length <= 80 && it.identityKey.size == 33 && GhostID.fromIdentityKey(it.identityKey) == it.ghostID }
    }

    override fun equals(other: Any?) = other is PrivatePayload && other.id == id && other.kind == kind && other.sender == sender && other.recipient == recipient
    override fun hashCode() = id.hashCode()

    companion object {
        const val MAX_LIFETIME_MS = 86_400_000L

        fun checkContent(text: String?, photo: ByteArray?, voice: ByteArray?, file: FileAttachment?) {
            if (text != null && (text.isBlank() || text.toByteArray(Charsets.UTF_8).size > Limits.maxTextBytes)) throw GhostError.TooLarge
            if (photo != null && (photo.isEmpty() || photo.size > Limits.maxPhotoBytes)) throw GhostError.TooLarge
            if (voice != null) {
                if (voice.size > Limits.maxVoiceBytes) throw GhostError.TooLarge
                if (!WAV.isValid(voice)) throw GhostError.InvalidPayload
            }
            if (file != null) {
                if (file.data.size > Limits.maxFileBytes) throw GhostError.TooLarge
                if (!file.isWellFormed) throw GhostError.InvalidPayload
            }
        }

        fun content(
            sender: GhostID, recipient: GhostID, content: Content, lifetimeMs: Long = MAX_LIFETIME_MS,
            now: Long = System.currentTimeMillis(), id: UUID = UUID.randomUUID(), group: String? = null, forwarded: Boolean = false,
            quote: Quote? = null,
        ): PrivatePayload {
            if (quote != null && !quote.isWellFormed) throw GhostError.InvalidPayload
            if (lifetimeMs <= 0 || lifetimeMs > MAX_LIFETIME_MS) throw GhostError.InvalidPayload
            if (group != null && !GhostGroup.isValidID(group)) throw GhostError.InvalidPayload
            val (kind, text, photo, voice, file) = when (content) {
                is Content.Text -> Quint(PayloadKind.text, content.value, null, null, null)
                is Content.Photo -> Quint(PayloadKind.photo, null, content.data, null, null)
                is Content.Voice -> Quint(PayloadKind.voice, null, null, content.data, null)
                is Content.File -> Quint(PayloadKind.file, null, null, null, content.attachment)
            }
            checkContent(text, photo, voice, file)
            return PrivatePayload(2, kind, id, sender, recipient, now, now + lifetimeMs, text, photo, voice, file,
                group = group?.let { GroupInfo(id = it) }, forwarded = if (forwarded) true else null, quote = quote)
        }

        /** First message on a one-time invitation: tells the inviter where to answer. */
        fun hello(sender: GhostID, recipient: GhostID, reply: ReplyAddress, now: Long = System.currentTimeMillis()) =
            PrivatePayload(2, PayloadKind.hello, UUID.randomUUID(), sender, recipient, now, now + MAX_LIFETIME_MS, reply = reply)

        /** The inviter's answer: confirms the connection and secures the joiner's queue. */
        fun ready(sender: GhostID, recipient: GhostID, now: Long = System.currentTimeMillis()) =
            PrivatePayload(2, PayloadKind.ready, UUID.randomUUID(), sender, recipient, now, now + MAX_LIFETIME_MS)

        fun groupControl(kind: PayloadKind, sender: GhostID, recipient: GhostID, info: GroupInfo, now: Long = System.currentTimeMillis()) =
            PrivatePayload(2, kind, UUID.randomUUID(), sender, recipient, now, now + MAX_LIFETIME_MS, group = info)

        /** A reaction to message [target]; an empty emoji removes the sender's reaction. */
        fun reaction(sender: GhostID, recipient: GhostID, target: UUID, emoji: String, group: String? = null, now: Long = System.currentTimeMillis()) =
            PrivatePayload(2, PayloadKind.reaction, UUID.randomUUID(), sender, recipient, now, now + MAX_LIFETIME_MS,
                group = group?.let { GroupInfo(id = it) }, target = target, emoji = emoji)

        /** The sender takes back one of their own messages. */
        fun retraction(sender: GhostID, recipient: GhostID, target: UUID, group: String? = null, now: Long = System.currentTimeMillis()) =
            PrivatePayload(2, PayloadKind.retract, UUID.randomUUID(), sender, recipient, now, now + MAX_LIFETIME_MS,
                group = group?.let { GroupInfo(id = it) }, target = target)
    }
}

private data class Quint(val kind: PayloadKind, val text: String?, val photo: ByteArray?, val voice: ByteArray?, val file: FileAttachment?)
