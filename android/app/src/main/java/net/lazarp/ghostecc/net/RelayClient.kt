package net.lazarp.ghostecc.net

import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import net.lazarp.ghostecc.core.Base64Bytes
import net.lazarp.ghostecc.core.Base64Url
import net.lazarp.ghostecc.core.GhostError
import net.lazarp.ghostecc.core.InboundQueue
import net.lazarp.ghostecc.core.Limits
import net.lazarp.ghostecc.core.OutboundQueue
import net.lazarp.ghostecc.core.RelayOrigin
import net.lazarp.ghostecc.core.RelayQueueID
import net.lazarp.ghostecc.core.RelaySigning
import net.lazarp.ghostecc.core.SecureRandomBytes
import net.lazarp.ghostecc.core.WireJson
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** Ed25519 queue keys. The private key is the 32-byte seed, the same form CryptoKit stores on iOS. */
object Ed25519 {
    fun generate(): ByteArray = SecureRandomBytes.bytes(32)
    fun publicKey(seed: ByteArray): ByteArray = Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded
    fun sign(seed: ByteArray, message: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(seed, 0))
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }
}

@Serializable data class RelayAuth(val timestamp: Long, val nonce: String, @Serializable(with = Base64Bytes::class) val signature: ByteArray)
@Serializable data class RelayQueueStatus(val recipientId: String, val status: String)
@Serializable data class RelayMessage(val recipientId: String, val id: String, @Serializable(with = Base64Bytes::class) val message: ByteArray, val expiresAt: Long)
@Serializable data class FetchResult(val queues: List<RelayQueueStatus>, val messages: List<RelayMessage>, val serverTime: Long)

@Serializable private data class CreateQueueRequest(
    @Serializable(with = Base64Bytes::class) val recipientKey: ByteArray,
    @Serializable(with = Base64Bytes::class) val invitation: ByteArray? = null,
    val auth: RelayAuth,
)
@Serializable private data class CreateQueueResponse(val recipientId: String, val senderId: String)
@Serializable private data class InvitationResponse(@Serializable(with = Base64Bytes::class) val invitation: ByteArray)
@Serializable private data class SendRequest(
    @Serializable(with = Base64Bytes::class) val message: ByteArray,
    val expiresAt: Long,
    @Serializable(with = Base64Bytes::class) val senderKey: ByteArray? = null,
    val auth: RelayAuth,
)
@Serializable private data class SendResponse(val id: String, val status: String)
@Serializable private data class FetchItem(val recipientId: String, val auth: RelayAuth)
@Serializable private data class FetchRequest(val queues: List<FetchItem>)
@Serializable private data class AckRequest(val recipientId: String, val ids: List<String>, val auth: RelayAuth)
@Serializable private data class DeleteRequest(val recipientId: String, val auth: RelayAuth)
@Serializable private data class NotifyRequest(val token: String? = null, val environment: String, val queues: List<FetchItem>)
@Serializable private data class NotifyResponse(val queues: List<RelayQueueStatus>)
@Serializable private data class HealthResponse(val status: String)
@Serializable private data class ServerTime(val serverTime: Long = 0)
@Serializable private data class ErrorResponse(val error: String = "")

private class ClockSkew : Exception()

/**
 * One relay server. Every queue operation is signed with that queue's own Ed25519 key, so the server
 * authorizes requests without accounts and without learning any Ghost ID. See docs/RELAY-PROTOCOL.md.
 */
class RelayClient(origin: String, private val http: OkHttpClient = DEFAULT_HTTP) {
    val origin: String = RelayOrigin.normalize(origin)
    @Volatile private var clockOffsetMs = 0L

    suspend fun health() {
        val response: HealthResponse = decode(perform(get("v1/health")))
        if (response.status != "ok") throw GhostError.Unavailable
    }

    suspend fun createQueue(invitation: ByteArray?): InboundQueue {
        val key = Ed25519.generate()
        val publicKey = Ed25519.publicKey(key)
        val digestInput = if (invitation != null) publicKey + invitation else publicKey
        val response: CreateQueueResponse = post("v1/queues") {
            WireJson.encodeToString(CreateQueueRequest(publicKey, invitation, auth(key, "create", "-", digestInput)))
        }
        if (!RelayQueueID.isValid(response.recipientId) || !RelayQueueID.isValid(response.senderId) || response.recipientId == response.senderId) {
            throw GhostError.InvalidPayload
        }
        return InboundQueue(origin, response.recipientId, response.senderId, key)
    }

    suspend fun invitation(senderID: String): ByteArray {
        if (!RelayQueueID.isValid(senderID)) throw GhostError.InvalidInvite
        return try {
            val response: InvitationResponse = decode(perform(get("v1/invitations/$senderID")))
            if (response.invitation.isEmpty() || response.invitation.size > 16_384) throw GhostError.InvalidInvite
            response.invitation
        } catch (e: GhostError.QueueGone) { throw GhostError.InvitationUsed }
    }

    suspend fun send(message: ByteArray, queue: OutboundQueue, expiresAtMs: Long) {
        if (queue.server != origin || !RelayQueueID.isValid(queue.senderID)) throw GhostError.InvalidPayload
        if (message.isEmpty() || message.size > Limits.maxWireBytes) throw GhostError.TooLarge
        // Until the queue is secured, the sender key travels with the request; the first valid sender owns the queue.
        val offeredKey = if (queue.secured) null else Ed25519.publicKey(queue.senderKey)
        var digestInput = message + "|$expiresAtMs|".toByteArray(Charsets.UTF_8)
        if (offeredKey != null) digestInput += offeredKey
        val response: SendResponse = post("v1/messages/${queue.senderID}") {
            WireJson.encodeToString(SendRequest(message, expiresAtMs, offeredKey, auth(queue.senderKey, "send", queue.senderID, digestInput)))
        }
        if (response.status != "accepted" || !RelayQueueID.isValidMessage(response.id)) throw GhostError.InvalidPayload
    }

    /** Up to 64 own queues in one request; per-queue failures come back as statuses. */
    suspend fun fetch(queues: List<InboundQueue>): FetchResult {
        if (queues.isEmpty() || queues.size > MAX_FETCH_QUEUES || queues.any { it.server != origin }) throw GhostError.InvalidPayload
        val result: FetchResult = post("v1/fetch") {
            WireJson.encodeToString(FetchRequest(queues.map { FetchItem(it.recipientID, auth(it.recipientKey, "fetch", it.recipientID, ByteArray(0))) }))
        }
        val requested = queues.map { it.recipientID }.toSet()
        if (!result.messages.all { it.recipientId in requested && RelayQueueID.isValidMessage(it.id) && it.message.size <= Limits.maxWireBytes } ||
            !result.queues.all { it.recipientId in requested }) throw GhostError.InvalidPayload
        return result
    }

    suspend fun ack(queue: InboundQueue, ids: List<String>) {
        if (queue.server != origin) throw GhostError.InvalidPayload
        val valid = ids.filter { RelayQueueID.isValidMessage(it) }
        for (chunk in valid.chunked(100)) {
            post<ServerTime>("v1/ack") {
                WireJson.encodeToString(AckRequest(queue.recipientID, chunk,
                    auth(queue.recipientKey, "ack", queue.recipientID, chunk.joinToString(",").toByteArray(Charsets.UTF_8))))
            }
        }
    }

    suspend fun delete(queue: InboundQueue) {
        if (queue.server != origin) throw GhostError.InvalidPayload
        try {
            post<ServerTime>("v1/delete") { WireJson.encodeToString(DeleteRequest(queue.recipientID, auth(queue.recipientKey, "delete", queue.recipientID, ByteArray(0)))) }
        } catch (e: GhostError.QueueGone) { /* already gone */ }
    }

    /** Binds this device's push token to own queues (RAM-only on the server), or removes it when token is null. */
    suspend fun notify(queues: List<InboundQueue>, token: String?, environment: String): List<RelayQueueStatus> {
        if (queues.isEmpty() || queues.size > MAX_FETCH_QUEUES || queues.any { it.server != origin }) throw GhostError.InvalidPayload
        val input = notifyDigestInput(token, environment)
        val response: NotifyResponse = post("v1/notify") {
            WireJson.encodeToString(NotifyRequest(token, environment, queues.map { FetchItem(it.recipientID, auth(it.recipientKey, "notify", it.recipientID, input)) }))
        }
        return response.queues
    }

    // MARK: Transport

    private fun auth(key: ByteArray, op: String, queueID: String, digestInput: ByteArray): RelayAuth {
        val timestamp = System.currentTimeMillis() + clockOffsetMs
        val nonce = Base64Url.encode(SecureRandomBytes.bytes(16))
        val message = RelaySigning.message(origin, op, queueID, timestamp, nonce, RelaySigning.digest(digestInput))
        return RelayAuth(timestamp, nonce, Ed25519.sign(key, message))
    }

    /** The body is built twice at most: a clock_skew answer corrects the offset, then the request is signed again once. */
    private suspend inline fun <reified T> post(path: String, crossinline body: () -> String): T {
        return try {
            decode(perform(postRequest(path, body())))
        } catch (e: ClockSkew) {
            try { decode(perform(postRequest(path, body()))) } catch (again: ClockSkew) { throw GhostError.ClockSkew }
        }
    }

    private inline fun <reified T> decode(bytes: ByteArray): T =
        try { WireJson.decodeFromString<T>(bytes.toString(Charsets.UTF_8)) } catch (e: Exception) { throw GhostError.InvalidPayload }

    private fun get(path: String): Request =
        Request.Builder().url("$origin/$path").get().header("Accept", "application/json").header("Cache-Control", "no-store").build()

    private fun postRequest(path: String, json: String): Request =
        Request.Builder().url("$origin/$path").post(json.toRequestBody(JSON))
            .header("Accept", "application/json").header("Cache-Control", "no-store").build()

    private suspend fun perform(request: Request): ByteArray {
        val response = try { http.newCall(request).await() } catch (e: IOException) { throw GhostError.Unavailable }
        response.use {
            val body = it.body?.bytes() ?: ByteArray(0)
            if (body.size > 13_000_000) throw GhostError.TooLarge
            runCatching { WireJson.decodeFromString<ServerTime>(body.toString(Charsets.UTF_8)) }.getOrNull()
                ?.let { time -> if (time.serverTime > 0) clockOffsetMs = time.serverTime - System.currentTimeMillis() }
            if (it.code in 200..299) return body
            val code = runCatching { WireJson.decodeFromString<ErrorResponse>(body.toString(Charsets.UTF_8)).error }.getOrNull()
            throw when {
                it.code == 401 && code == "clock_skew" -> ClockSkew()
                it.code == 401 || it.code == 409 -> GhostError.Unauthorized
                it.code == 404 -> GhostError.QueueGone
                it.code == 413 -> GhostError.TooLarge
                it.code == 429 -> GhostError.RateLimited
                it.code == 503 -> GhostError.Unavailable
                else -> GhostError.Server(it.code)
            }
        }
    }

    companion object {
        const val MAX_FETCH_QUEUES = 64
        private val JSON = "application/json".toMediaType()
        fun notifyDigestInput(token: String?, environment: String): ByteArray = "${token ?: ""}|$environment".toByteArray(Charsets.UTF_8)

        /** No cache, no cookies, no redirects: nothing about the relay traffic is kept on the device. */
        val DEFAULT_HTTP: OkHttpClient = OkHttpClient.Builder()
            .cache(null)
            .followRedirects(false).followSslRedirects(false)
            .connectTimeout(25, TimeUnit.SECONDS).readTimeout(25, TimeUnit.SECONDS).writeTimeout(60, TimeUnit.SECONDS)
            .callTimeout(60, TimeUnit.SECONDS)
            .build()
    }
}

/** Cancelling the coroutine cancels the HTTP call. */
private suspend fun Call.await(): Response = suspendCancellableCoroutine { continuation ->
    enqueue(object : Callback {
        override fun onResponse(call: Call, response: Response) = continuation.resume(response)
        override fun onFailure(call: Call, e: IOException) { if (continuation.isActive) continuation.resumeWithException(e) }
    })
    continuation.invokeOnCancellation { runCatching { cancel() } }
}
