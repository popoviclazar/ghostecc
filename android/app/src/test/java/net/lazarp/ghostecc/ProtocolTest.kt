package net.lazarp.ghostecc

import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import net.lazarp.ghostecc.core.Content
import net.lazarp.ghostecc.core.FileAttachment
import net.lazarp.ghostecc.core.GhostError
import net.lazarp.ghostecc.core.GhostGroup
import net.lazarp.ghostecc.core.GhostID
import net.lazarp.ghostecc.core.GroupInfo
import net.lazarp.ghostecc.core.GroupMember
import net.lazarp.ghostecc.core.InviteCrypto
import net.lazarp.ghostecc.core.InviteLink
import net.lazarp.ghostecc.core.KeyBundleDTO
import net.lazarp.ghostecc.core.PayloadKind
import net.lazarp.ghostecc.core.PrivatePayload
import net.lazarp.ghostecc.core.PublicPreKey
import net.lazarp.ghostecc.core.PublicSignedPreKey
import net.lazarp.ghostecc.core.RelayOrigin
import net.lazarp.ghostecc.core.RelaySigning
import net.lazarp.ghostecc.core.SafetyCode
import net.lazarp.ghostecc.core.WAV
import net.lazarp.ghostecc.core.WireEnvelope
import net.lazarp.ghostecc.core.WireJson
import net.lazarp.ghostecc.core.WirePadding
import net.lazarp.ghostecc.net.Ed25519
import net.lazarp.ghostecc.net.RelayClient
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

/** Compatibility with the iOS app and the relay, using vectors in exactly the form iOS and the server produce. */
class ProtocolTest {
    private val aliceKey = ByteArray(33) { 1 }
    private val bobKey = ByteArray(33) { 2 }
    private val alice = GhostID("GHOST-CE041765675AD4D93378E20BD3A7D0D97DDCF3385FB6341581B21D4BC9E3E69E")
    private val bob = GhostID("GHOST-7F2F54FF94459F3AC4D19D3219CE6EF06868EB8C72E6D84CC358BC769B23113A")

    @Test fun ghostIdIsSha256OfTheIdentityKey() {
        assertEquals(alice, GhostID.fromIdentityKey(aliceKey))
        assertEquals(bob, GhostID.fromIdentityKey(bobKey))
        assertThrows(GhostError.InvalidID::class.java) { GhostID.parse("GHOST-123") }
        assertEquals(alice, GhostID.parse(" " + alice.rawValue.lowercase() + "\n"))
    }

    @Test fun relaySignatureMatchesProtocolVector() {
        val digest = RelaySigning.digest("hello".toByteArray())
        assertEquals("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", digest)
        val message = RelaySigning.message("https://relay.example.com", "fetch", "Q", 1_700_000_000_000, "N", digest)
        assertEquals("GHOST-RELAY-v1\nhttps://relay.example.com\nfetch\nQ\n1700000000000\nN\n$digest", message.toString(Charsets.UTF_8))
        assertArrayEquals("|apns|".toByteArray(), RelayClient.notifyDigestInput(null, "apns"))
    }

    @Test fun ed25519SignaturesVerifyWithStandardKeys() {
        val seed = Ed25519.generate()
        val message = "GHOST-RELAY-v1".toByteArray()
        val signature = Ed25519.sign(seed, message)
        assertEquals(64, signature.size)
        val verifier = org.bouncycastle.crypto.signers.Ed25519Signer()
        verifier.init(false, org.bouncycastle.crypto.params.Ed25519PublicKeyParameters(Ed25519.publicKey(seed), 0))
        verifier.update(message, 0, message.size)
        assertTrue(verifier.verifySignature(signature))
    }

    @Test fun originsAreNormalizedLikeTheServer() {
        assertEquals("https://relay.example.com", RelayOrigin.normalize("HTTPS://Relay.Example.com/"))
        assertEquals("https://relay.example.com:8443", RelayOrigin.normalize("https://relay.example.com:8443"))
        assertEquals("https://relay.example.com", RelayOrigin.normalize("https://relay.example.com:443"))
        for (bad in listOf("http://relay.example.com", "https://user@relay.example.com", "https://relay.example.com/path", "https://relay.example.com?q=1")) {
            assertThrows(GhostError.InvalidURL::class.java) { RelayOrigin.normalize(bad) }
        }
    }

    @Test fun paddingUsesTheSameBuckets() {
        assertEquals(1_024, WirePadding.bucket(0))
        assertEquals(1_024, WirePadding.bucket(1_020))
        assertEquals(4_096, WirePadding.bucket(1_021))
        assertEquals(65_536, WirePadding.bucket(65_532))
        assertEquals(262_144, WirePadding.bucket(65_533))
        assertEquals(524_288, WirePadding.bucket(262_141))
        val data = "Ghost".toByteArray()
        val padded = WirePadding.pad(data)
        assertEquals(1_024, padded.size)
        assertArrayEquals(byteArrayOf(0, 0, 0, 5), padded.copyOfRange(0, 4))
        assertArrayEquals(data, WirePadding.unpad(padded))
        val envelope = WireEnvelope.parse(byteArrayOf(2, 3, 9, 9))
        assertEquals(3, envelope.messageType)
        assertThrows(GhostError.InvalidPayload::class.java) { WireEnvelope.parse(byteArrayOf(1, 3, 9)) }
    }

    /** iOS writes milliseconds with a fraction, upper-case UUIDs, sorted keys and escapes "/" as "\/". */
    @Test fun decodesPayloadExactlyAsIosWritesIt() {
        val json = """{"expiresAt":1762386400123.456,"id":"E621E1F8-C36C-495A-93FC-0C247A3E6E5F","kind":"photo",""" +
            """"photo":"AAEC\/w==","recipient":"${bob.rawValue}","sender":"${alice.rawValue}","sentAt":1762300000123.456,"version":2}"""
        val payload = WireJson.decodeFromString<PrivatePayload>(json)
        assertEquals(PayloadKind.photo, payload.kind)
        assertEquals(1_762_300_000_123, payload.sentAt)
        assertEquals(UUID.fromString("E621E1F8-C36C-495A-93FC-0C247A3E6E5F"), payload.id)
        assertArrayEquals(byteArrayOf(0, 1, 2, -1), payload.photo)
        payload.validate(alice, bob, now = 1_762_300_001_000)
        val encoded = WireJson.encodeToString(payload)
        assertTrue(encoded.contains("\"id\":\"E621E1F8-C36C-495A-93FC-0C247A3E6E5F\""))
        assertFalse("absent optionals are omitted, as on iOS", encoded.contains("null"))
    }

    @Test fun parsesInviteLinkMadeByIos() {
        val link = InviteLink.parse("ghost-ecc://invite/eyJrIjoiQlFjSEJ3Y0hCd2NIQndjSEJ3Y0hCd2NIQndjSEJ3Y0hCd2NIQndjSEJ3Y0giLCJxIjoiUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVEiLCJzIjoiaHR0cHM6XC9cL3JlbGF5LmV4YW1wbGUuY29tIiwidiI6MSwieCI6IkNRa0pDUWtKQ1FrSkNRa0pDUWtKQ1FrSkNRa0pDUWtKQ1FrSkNRa0pDUWs9In0")
        assertEquals("https://relay.example.com", link.s)
        assertEquals("Q".repeat(32), link.q)
        assertEquals(GhostID("GHOST-218C1E8DCF54D413C6959A150EAD67DFFE0AC4DA38505AF06856ACA9ACB754DB"), link.ghostID)
        val again = InviteLink.parse(link.string())
        assertEquals(link.ghostID, again.ghostID); assertEquals(link.q, again.q); assertEquals(link.s, again.s)
        assertArrayEquals(link.x, again.x)
        assertThrows(GhostError.InvalidInvite::class.java) { InviteLink.parse("ghost-ecc://invite/xyz") }
    }

    @Test fun sealedBundleOpensOnlyWithTheLinkKey() {
        val identityKey = ByteArray(33) { 5 }.also { it[0] = 5 }
        val bundle = KeyBundleDTO(GhostID.fromIdentityKey(identityKey), 7, 1, identityKey,
            PublicPreKey(11, ByteArray(33) { 1 }), PublicSignedPreKey(11, ByteArray(33) { 2 }, ByteArray(64) { 3 }),
            PublicSignedPreKey(11, ByteArray(1569) { 4 }, ByteArray(64) { 5 }))
        val key = ByteArray(32) { 9 }
        val link = InviteLink(identityKey, "Q".repeat(32), "https://relay.example.com", 1, key)
        val sealed = InviteCrypto.seal(bundle, key)
        assertEquals(bundle.id, InviteCrypto.open(sealed, link).id)
        assertThrows(GhostError.InvalidInvite::class.java) { InviteCrypto.open(sealed, link.copy(x = ByteArray(32) { 8 })) }
        val otherIdentity = ByteArray(33) { 6 }
        assertThrows(GhostError.InvalidInvite::class.java) { InviteCrypto.open(sealed, link.copy(k = otherIdentity)) }
    }

    @Test fun contentRulesMatchIos() {
        val text = PrivatePayload.content(alice, bob, Content.Text("hi"), group = GhostGroup.newID(), forwarded = true)
        text.validate(alice, bob)
        assertEquals(true, text.forwarded)
        assertThrows(GhostError.InvalidPayload::class.java) { PrivatePayload.content(alice, bob, Content.Text("hi"), group = "bad") }
        assertThrows(GhostError.TooLarge::class.java) { PrivatePayload.content(alice, bob, Content.Text("   ")) }
        val wav = WAV.wrap(ByteArray(32_000))
        assertEquals(1.0, WAV.durationSeconds(wav), 0.001)
        PrivatePayload.content(alice, bob, Content.Voice(wav)).validate(alice, bob)
        assertThrows(GhostError.InvalidPayload::class.java) { PrivatePayload.content(alice, bob, Content.Voice(ByteArray(500) { 1 })) }
        assertEquals("_.._etc_passwd", FileAttachment.cleanName("../../etc/passwd"))
        assertEquals("file", FileAttachment.cleanName("  "))
        assertEquals("com.adobe.pdf", FileAttachment.typeIdentifier("application/pdf"))
        val file = FileAttachment("report.pdf", FileAttachment.typeIdentifier("application/pdf"), byteArrayOf(1, 2, 3))
        PrivatePayload.content(alice, bob, Content.File(file)).validate(alice, bob)
        assertThrows(GhostError.InvalidPayload::class.java) {
            PrivatePayload.content(alice, bob, Content.File(FileAttachment("x.pdf", "application/pdf", byteArrayOf(1))))
        }
    }

    @Test fun groupRulesMatchIos() {
        val gid = GhostGroup.newID()
        val members = listOf(GroupMember(alice, "", aliceKey), GroupMember(bob, "Bob", bobKey))
        PrivatePayload.groupControl(PayloadKind.groupUpdate, alice, bob, GroupInfo(gid, "Team", alice, members)).validate(alice, bob)
        assertThrows(GhostError.InvalidPayload::class.java) {
            PrivatePayload.groupControl(PayloadKind.groupUpdate, bob, alice, GroupInfo(gid, "Team", alice, members)).validate(bob, alice)
        }
        val wrongKey = listOf(GroupMember(alice, "", bobKey), members[1])
        assertThrows(GhostError.InvalidPayload::class.java) {
            PrivatePayload.groupControl(PayloadKind.groupUpdate, alice, bob, GroupInfo(gid, "Team", alice, wrongKey)).validate(alice, bob)
        }
        PrivatePayload.groupControl(PayloadKind.groupLeave, bob, alice, GroupInfo(gid)).validate(bob, alice)
        assertThrows(GhostError.InvalidPayload::class.java) {
            PrivatePayload.groupControl(PayloadKind.groupIntro, bob, alice, GroupInfo(gid, introFor = alice, link = "nope")).validate(bob, alice)
        }
        // Group content cannot carry membership changes.
        val content = PrivatePayload.content(alice, bob, Content.Text("hi"), group = gid)
        assertThrows(GhostError.InvalidPayload::class.java) { content.copy(group = GroupInfo(gid, name = "x")).validate(alice, bob) }
    }

    @Test fun repliesReactionsAndRetractionsMatchIos() {
        val reactionJson = """{"emoji":"❤️","expiresAt":1762386400123.5,"id":"0B7C1D5E-1111-4222-8333-944455556666","kind":"reaction",""" +
            """"recipient":"${bob.rawValue}","sender":"${alice.rawValue}","sentAt":1762300000123.5,"target":"E621E1F8-C36C-495A-93FC-0C247A3E6E5F","version":2}"""
        val reaction = WireJson.decodeFromString<PrivatePayload>(reactionJson)
        reaction.validate(alice, bob, now = 1_762_300_001_000)
        assertEquals("❤️", reaction.emoji)
        PrivatePayload.retraction(alice, bob, UUID.randomUUID(), group = GhostGroup.newID()).validate(alice, bob)
        val original = PrivatePayload.content(alice, bob, Content.Text("hi"))
        val reply = PrivatePayload.content(bob, alice, Content.Text("hello"), quote = net.lazarp.ghostecc.core.Quote(original.id, alice, "hi"))
        reply.validate(bob, alice)
        assertThrows(GhostError.InvalidPayload::class.java) { reaction.copy(text = "smuggled").validate(alice, bob, now = 1_762_300_001_000) }
        assertThrows(GhostError.InvalidPayload::class.java) { original.copy(target = UUID.randomUUID()).validate(alice, bob) }
    }

    @Test fun safetyCodeQr() {
        val number = "12345 ".repeat(12)
        val link = SafetyCode.link(number)
        assertEquals("ghost-ecc://verify/" + "12345".repeat(12), link)
        assertTrue(SafetyCode.matches(link, number))
        assertFalse(SafetyCode.matches(link + "0", number))
        assertNotNull(GhostGroup.newID().takeIf { GhostGroup.isValidID(it) })
    }
}
