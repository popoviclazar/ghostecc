package net.lazarp.ghostecc

import kotlinx.coroutines.test.runTest
import net.lazarp.ghostecc.core.Content
import net.lazarp.ghostecc.core.GhostError
import net.lazarp.ghostecc.core.GhostGroup
import net.lazarp.ghostecc.core.PayloadKind
import net.lazarp.ghostecc.core.PrivatePayload
import net.lazarp.ghostecc.core.ReplyAddress
import net.lazarp.ghostecc.core.WAV
import net.lazarp.ghostecc.security.MemoryVault
import net.lazarp.ghostecc.security.SignalEngine
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Runs on the Mac (libsignal-client carries the desktop native library). */
class SignalEngineTest {
    private val reply = ReplyAddress("https://relay.example.com", "A".repeat(32))

    @Test fun invitationHandshakeAndMessagesBothWays() = runTest {
        val aliceVault = MemoryVault()
        val alice = SignalEngine(aliceVault)
        val bob = SignalEngine(MemoryVault())
        val (a, aKey) = alice.loadIdentity(create = true)!!
        val (b, bKey) = bob.loadIdentity(create = true)!!

        // Bob invites, Alice joins with hello (PreKey message), Bob answers ready.
        val bundle = bob.invitationBundle()
        assertTrue("IDs fit Java's signed int", bundle.preKey.id in 1..0x7FFF_FFFFL && bundle.kyberPreKey.id in 1..0x7FFF_FFFFL)
        alice.prepareSession(bundle)
        val hello = bob.decrypt(alice.encrypt(PrivatePayload.hello(a, b, reply)), expectedKey = null)
        assertEquals(PayloadKind.hello, hello.payload.kind)
        assertArrayEquals(aKey, hello.senderKey)
        assertEquals("one-time keys are gone after use", Triple(0, 0, 1), bob.keyMaterialCounts())
        alice.decrypt(bob.encrypt(PrivatePayload.ready(b, a)), expectedKey = bKey)

        val text = bob.decrypt(alice.encrypt(PrivatePayload.content(a, b, Content.Text("Zdravo 👋"))), expectedKey = aKey)
        assertEquals("Zdravo 👋", text.payload.text)
        val wav = WAV.wrap(ByteArray(64_000) { (it % 251).toByte() })
        val voice = alice.decrypt(bob.encrypt(PrivatePayload.content(b, a, Content.Voice(wav), group = GhostGroup.newID(), forwarded = true)), expectedKey = bKey)
        assertArrayEquals(wav, voice.payload.voice)
        assertEquals(true, voice.payload.forwarded)

        // Same 60 digits on both phones.
        val numberA = alice.safetyNumber(b, bKey)
        assertEquals(60, numberA.length)
        assertEquals(numberA, bob.safetyNumber(a, aKey))

        // State survives a restart: a new engine on the same storage continues the ratchet.
        val restarted = SignalEngine(aliceVault)
        restarted.loadIdentity()
        val after = bob.decrypt(restarted.encrypt(PrivatePayload.content(a, b, Content.Text("after restart"))), expectedKey = aKey)
        assertEquals("after restart", after.payload.text)
    }

    @Test fun tamperedMessageIsRejectedWithoutBreakingTheSession() = runTest {
        val alice = SignalEngine(MemoryVault())
        val bob = SignalEngine(MemoryVault())
        val (a, aKey) = alice.loadIdentity(create = true)!!
        val (b, bKey) = bob.loadIdentity(create = true)!!
        alice.prepareSession(bob.invitationBundle())
        bob.decrypt(alice.encrypt(PrivatePayload.hello(a, b, reply)), expectedKey = null)
        alice.decrypt(bob.encrypt(PrivatePayload.ready(b, a)), expectedKey = bKey)

        val wire = alice.encrypt(PrivatePayload.content(a, b, Content.Text("one")))
        val tampered = wire.copyOf().also { it[it.size - 5] = (it[it.size - 5].toInt() xor 1).toByte() }
        try { bob.decrypt(tampered, expectedKey = aKey); fail("tampered message accepted") } catch (e: GhostError) { /* expected */ }
        assertEquals("one", bob.decrypt(wire, expectedKey = aKey).payload.text)
        // A wrong pinned key is refused.
        try { bob.decrypt(alice.encrypt(PrivatePayload.content(a, b, Content.Text("x"))), expectedKey = bKey); fail("wrong key accepted") }
        catch (e: GhostError) { /* expected */ }
    }

    @Test fun firstMessageOnAnInvitationMustBeHello() = runTest {
        val alice = SignalEngine(MemoryVault())
        val bob = SignalEngine(MemoryVault())
        val (a, _) = alice.loadIdentity(create = true)!!
        val (b, _) = bob.loadIdentity(create = true)!!
        alice.prepareSession(bob.invitationBundle())
        try {
            bob.decrypt(alice.encrypt(PrivatePayload.content(a, b, Content.Text("not hello"))), expectedKey = null)
            fail("content accepted before hello")
        } catch (e: GhostError.InvalidPayload) { /* expected */ }
    }

    @Test fun oversizedKeyIdsFromOldInvitationsAreRefused() = runTest {
        val alice = SignalEngine(MemoryVault())
        val bob = SignalEngine(MemoryVault())
        alice.loadIdentity(create = true)
        bob.loadIdentity(create = true)
        val bundle = bob.invitationBundle()
        val old = bundle.copy(preKey = bundle.preKey.copy(id = 3_000_000_000))
        try { alice.prepareSession(old); fail("accepted an ID above 2^31") } catch (e: GhostError.InvalidInvite) { /* expected */ }
    }
}
