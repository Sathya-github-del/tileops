package dev.tileops.app.data

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Encrypts small secrets. Blob format: [version=1][12-byte IV][AES-GCM ciphertext+tag]. */
interface TokenCipher {
    fun encrypt(plain: ByteArray): ByteArray
    fun decrypt(blob: ByteArray): ByteArray
}

open class AesGcmTokenCipher(private val keyProvider: () -> SecretKey) : TokenCipher {
    private companion object {
        const val VERSION: Byte = 1
        const val IV_LEN = 12
        const val TAG_BITS = 128
    }

    override fun encrypt(plain: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, keyProvider())
        val iv = c.iv
        require(iv.size == IV_LEN) { "unexpected IV length" }
        return byteArrayOf(VERSION) + iv + c.doFinal(plain)
    }

    override fun decrypt(blob: ByteArray): ByteArray {
        require(blob.size > 1 + IV_LEN && blob[0] == VERSION) { "bad token blob" }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, keyProvider(), GCMParameterSpec(TAG_BITS, blob, 1, IV_LEN))
        return c.doFinal(blob, 1 + IV_LEN, blob.size - 1 - IV_LEN)
    }
}

/** AES-256-GCM key that never leaves the Android Keystore (not exportable, not backed up). */
class KeystoreTokenCipher(alias: String = "tileops_token_key") : AesGcmTokenCipher({ keystoreKey(alias) }) {
    companion object {
        private fun keystoreKey(alias: String): SecretKey {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            (ks.getKey(alias, null) as? SecretKey)?.let { return it }
            val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            gen.init(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
            )
            return gen.generateKey()
        }
    }
}

/**
 * Pairing storage: companion URL in plain text, bearer token encrypted with a Keystore-backed
 * key, both in Preferences DataStore. (EncryptedSharedPreferences is deprecated, so not used.)
 */
class TokenStore(private val store: DataStore<Preferences>, private val cipher: TokenCipher) {
    private val urlKey = stringPreferencesKey("base_url")
    private val tokenKey = stringPreferencesKey("token_enc")
    private val modeKey = stringPreferencesKey("mode")
    private val pinKey = stringPreferencesKey("cert_pin")

    /** "local" = phone only, "companion" = always-on companion, null = not chosen yet. */
    val mode: Flow<String?> = store.data.map { it[modeKey] }

    suspend fun setMode(mode: String?) {
        store.edit { if (mode == null) it.remove(modeKey) else it[modeKey] = mode }
    }

    /** Forget the companion pairing but keep the chosen mode. */
    suspend fun clearPairing() {
        store.edit { it.remove(urlKey); it.remove(tokenKey); it.remove(pinKey) }
    }

    val pairing: Flow<Pairing?> = store.data.map { prefs ->
        val url = prefs[urlKey] ?: return@map null
        val enc = prefs[tokenKey] ?: return@map null
        runCatching { Pairing(url, String(cipher.decrypt(Base64.getDecoder().decode(enc)), Charsets.UTF_8), prefs[pinKey]) }
            .getOrNull() // key lost (e.g. app data restored elsewhere) -> treated as unpaired
    }

    suspend fun get(): Pairing? = pairing.first()

    suspend fun save(p: Pairing) {
        val enc = Base64.getEncoder().encodeToString(cipher.encrypt(p.token.toByteArray(Charsets.UTF_8)))
        store.edit {
            it[urlKey] = ApiClient.normalizeUrl(p.baseUrl)
            it[tokenKey] = enc
            if (p.certPin != null) it[pinKey] = p.certPin else it.remove(pinKey)
        }
    }

    suspend fun clear() {
        store.edit { it.clear() }
    }
}
