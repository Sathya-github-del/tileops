package dev.tileops.app.ui

import org.junit.Assert.assertEquals
import org.junit.Test

class FriendlyAddressTest {
    @Test
    fun addsSchemeAndDefaultPortOnlyWhenMissing() {
        // bare addresses default to HTTPS: companions serve TLS by default
        assertEquals("https://192.168.1.20:8800", friendlyAddress("192.168.1.20"))
        assertEquals("https://192.168.1.20:9000", friendlyAddress("192.168.1.20:9000"))
        // an explicit scheme is kept
        assertEquals("http://192.168.1.20:8800", friendlyAddress(" http://192.168.1.20/ "))
        assertEquals("https://tileops.example.com:8800", friendlyAddress("https://tileops.example.com"))
        assertEquals("http://[fd00::5]:8800", friendlyAddress("http://[fd00::5]"))
        assertEquals("https://[fd00::5]:8801", friendlyAddress("https://[fd00::5]:8801"))
    }
}
