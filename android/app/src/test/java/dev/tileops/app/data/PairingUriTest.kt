package dev.tileops.app.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PairingUriTest {
    private val tok = "eaCg9C13NB5jSOiFJ_JMSnDSFIamTpK-XuHHRors6WI"

    @Test
    fun parsesCompanionQr() {
        val p = PairingUri.parse("tileops://pair?url=http%3A%2F%2F192.168.1.9%3A8800&token=$tok")
        assertEquals(Pairing("http://192.168.1.9:8800", tok), p)
    }

    @Test
    fun rejectsJunk() {
        assertNull(PairingUri.parse(null))
        assertNull(PairingUri.parse("https://evil.example/?url=x&token=$tok"))
        assertNull(PairingUri.parse("tileops://pair?url=javascript%3Aalert(1)&token=$tok"))
        assertNull(PairingUri.parse("tileops://pair?url=http%3A%2F%2Fh&token=short"))
        assertNull(PairingUri.parse("tileops://pair?url=http%3A%2F%2Fh&token=has%20space%20aaaaaaaaaaaaaa"))
        assertNull(PairingUri.parse("tileops://pair?token=$tok"))
    }

    @Test
    fun alertDeepLink() {
        assertEquals(42L, PairingUri.alertId("tileops://alert/42"))
        assertEquals(42L, PairingUri.alertId("tileops://alert/42/"))
        assertNull(PairingUri.alertId("tileops://alert/abc"))
        assertNull(PairingUri.alertId("tileops://pair?x"))
    }

    @Test
    fun extractsLinkFromPastedTerminalText() {
        val link = "tileops://pair?url=http%3A%2F%2F10.0.0.5%3A8800&token=$tok"
        assertEquals(Pairing("http://10.0.0.5:8800", tok), PairingUri.extract("     $link\n"))
        assertEquals(Pairing("http://10.0.0.5:8800", tok),
            PairingUri.extract("2) Or copy this pairing link and paste it in the app:\n     $link\n  3) Or type"))
        assertNull(PairingUri.extract("no link here"))
        assertNull(PairingUri.extract(null))
    }

    @Test
    fun certificatePinFromPairingLink() {
        val fp = "iDY1YlC0PQUh4P_uC3DGRKRlYXEFgc6aQPUyBTmF2_U"
        val p = PairingUri.parse("tileops://pair?url=https%3A%2F%2F192.168.1.7%3A8800&token=$tok&fp=$fp")
        assertEquals(Pairing("https://192.168.1.7:8800", tok, fp), p)
        assertNull(PairingUri.parse("tileops://pair?url=https%3A%2F%2Fh&token=$tok&fp=short"))
        assertEquals(null, PairingUri.parse("tileops://pair?url=http%3A%2F%2Fh&token=$tok")!!.certPin)
    }
}
