package dev.tileops.app.data

import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/** Token storage with the same AES-GCM format as the Keystore cipher, using a JCE key on the JVM. */
class TokenStoreTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val key: SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private val cipher = AesGcmTokenCipher { key }
    private val token = "eaCg9C13NB5jSOiFJ_JMSnDSFIamTpK-XuHHRors6WI"

    @Test
    fun cipherRoundTripUsesFreshIv() {
        val a = cipher.encrypt(token.toByteArray())
        val b = cipher.encrypt(token.toByteArray())
        assertNotEquals(a.toList(), b.toList())
        assertEquals(1, a[0].toInt())
        assertArrayEquals(token.toByteArray(), cipher.decrypt(a))
    }

    @Test(expected = Exception::class)
    fun tamperedCiphertextIsRejected() {
        val blob = cipher.encrypt(token.toByteArray())
        blob[blob.size - 1] = (blob[blob.size - 1].toInt() xor 1).toByte()
        cipher.decrypt(blob)
    }

    @Test
    fun saveLoadClear() = runTest {
        val file = tmp.newFile("pairing.preferences_pb").also { it.delete() }
        val ds = PreferenceDataStoreFactory.create(scope = backgroundScope, produceFile = { file })
        val store = TokenStore(ds, cipher)
        assertNull(store.get())

        store.save(Pairing("192.168.1.9:8800/", token))
        assertEquals(Pairing("http://192.168.1.9:8800", token), store.get())

        // the token never hits disk in plain text
        val raw = file.readBytes().decodeToString()
        assertFalse(raw.contains(token))

        val fp = "iDY1YlC0PQUh4P_uC3DGRKRlYXEFgc6aQPUyBTmF2_U"
        store.save(Pairing("https://192.168.1.7:8800", token, fp))
        assertEquals(fp, store.get()!!.certPin)
        store.save(Pairing("http://192.168.1.7:8800", token))
        assertNull(store.get()!!.certPin) // re-pairing without TLS clears the old pin

        store.clear()
        assertNull(store.get())
    }

    @Test
    fun wrongKeyMeansUnpairedNotCrash() = runTest {
        val file = tmp.newFile("p2.preferences_pb").also { it.delete() }
        val ds = PreferenceDataStoreFactory.create(scope = backgroundScope, produceFile = { file })
        TokenStore(ds, cipher).save(Pairing("http://h:8800", token))
        val otherKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        assertNull(TokenStore(ds, AesGcmTokenCipher { otherKey }).get())
    }
}
