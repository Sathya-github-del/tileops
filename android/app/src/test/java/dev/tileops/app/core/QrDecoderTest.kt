package dev.tileops.app.core

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class QrDecoderTest {
    private val link = "tileops://pair?url=https%3A%2F%2F192.168.1.7%3A8800" +
        "&token=eaCg9C13NB5jSOiFJ_JMSnDSFIamTpK-XuHHRors6WI&fp=iDY1YlC0PQUh4P_uC3DGRKRlYXEFgc6aQPUyBTmF2_U"

    /** Renders [text] as a QR code into a grey camera-like Y plane with padding bytes per row. */
    private fun frame(text: String, w: Int = 640, h: Int = 480, stride: Int = 704, dark: Boolean = false): ByteArray {
        val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 360, 360, mapOf(EncodeHintType.MARGIN to 2))
        val y = ByteArray(stride * h) { 0x77 }
        val ox = (w - m.width) / 2; val oy = (h - m.height) / 2
        for (r in 0 until h) for (c in 0 until w) {
            val inCode = c - ox in 0 until m.width && r - oy in 0 until m.height
            val black = inCode && m.get(c - ox, r - oy)
            val white = inCode && !black
            val v = when { black -> if (dark) 235 else 20; white -> if (dark) 20 else 235; else -> 0x77 }
            y[r * stride + c] = v.toByte()
        }
        return y
    }

    @Test
    fun decodesPairingLinkFromCameraFrame() {
        assertEquals(link, QrDecoder.decodeLuminance(frame(link), 640, 480, 704))
    }

    @Test
    fun decodesInvertedCode() {
        assertEquals(link, QrDecoder.decodeLuminance(frame(link, dark = true), 640, 480, 704))
    }

    @Test
    fun noCodeMeansNull() {
        assertNull(QrDecoder.decodeLuminance(ByteArray(640 * 480) { 0x40 }, 640, 480))
    }
}
