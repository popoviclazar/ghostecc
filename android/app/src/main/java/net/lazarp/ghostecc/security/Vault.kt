package net.lazarp.ghostecc.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import net.lazarp.ghostecc.core.GhostError
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Small named secrets: protocol state, metadata, passcode verifier. */
interface Vault {
    fun load(account: String): ByteArray?
    fun save(data: ByteArray, account: String)
    fun delete(account: String)
}

/** RAM only: Ghost Lab and tests. */
class MemoryVault : Vault {
    private val items = mutableMapOf<String, ByteArray>()
    @Synchronized override fun load(account: String) = items[account]?.copyOf()
    @Synchronized override fun save(data: ByteArray, account: String) { items[account] = data.copyOf() }
    @Synchronized override fun delete(account: String) { items.remove(account) }
}

/**
 * The Android counterpart of the iOS Keychain with "this device only": an AES-256-GCM key that lives in the
 * Android Keystore (hardware-backed where available, never exportable), and ciphertext files in the app's
 * no-backup directory, so nothing reaches cloud backups or device transfers.
 */
class KeystoreVault(context: Context) : Vault {
    private val dir = File(context.noBackupFilesDir, "vault").apply { mkdirs() }

    @Synchronized override fun load(account: String): ByteArray? {
        val file = file(account)
        if (!file.exists()) return null
        val blob = file.readBytes()
        if (blob.size < 12 + 16) throw GhostError.Storage
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, blob.copyOfRange(0, 12)))
            cipher.updateAAD(account.toByteArray(Charsets.UTF_8))
            cipher.doFinal(blob.copyOfRange(12, blob.size))
        } catch (e: Exception) { throw GhostError.Storage }
    }

    @Synchronized override fun save(data: ByteArray, account: String) {
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key())
            cipher.updateAAD(account.toByteArray(Charsets.UTF_8))
            val blob = cipher.iv + cipher.doFinal(data)
            // Write then rename, so a crash never leaves a half-written state file.
            val temp = File(dir, "${name(account)}.tmp")
            temp.writeBytes(blob)
            if (!temp.renameTo(file(account))) throw GhostError.Storage
        } catch (e: GhostError) { throw e } catch (e: Exception) { throw GhostError.Storage }
    }

    @Synchronized override fun delete(account: String) { file(account).delete() }

    /** Removes everything, including the Keystore key: used when the identity is deleted. */
    @Synchronized fun wipe() {
        dir.listFiles()?.forEach { it.delete() }
        runCatching { KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(ALIAS) }
    }

    private fun name(account: String) = account.replace(Regex("[^A-Za-z0-9_-]"), "_")
    private fun file(account: String) = File(dir, "${name(account)}.bin")

    private fun key(): SecretKey {
        val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (store.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return generator.generateKey()
    }

    companion object {
        private const val KEYSTORE = "AndroidKeyStore"
        private const val ALIAS = "ghostecc.vault.v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
