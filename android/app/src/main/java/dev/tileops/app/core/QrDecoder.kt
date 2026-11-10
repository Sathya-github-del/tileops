package dev.tileops.app.core

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader

/**
 * QR decoding with ZXing (Apache-2.0, pure Java), so the app has no proprietary
 * Google Play / ML Kit dependency and can be built by F-Droid.
 */
object QrDecoder {
    private val hints = mapOf(
        DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
        DecodeHintType.CHARACTER_SET to "UTF-8",
    )

    /**
     * Decodes a QR code from a camera frame's luminance (Y) plane.
     * [rowStride] is the number of bytes per row in [y] (>= [width]).
     * QR codes are rotation-invariant, so the frame rotation doesn't matter.
     */
    fun decodeLuminance(y: ByteArray, width: Int, height: Int, rowStride: Int = width): String? {
        val source = PlanarYUVLuminanceSource(y, rowStride, height, 0, 0, width, height, false)
        return decode(source) ?: decode(source.invert()) // also light-on-dark codes
    }

    private fun decode(source: LuminanceSource): String? {
        val reader = QRCodeReader()
        return try {
            reader.decode(BinaryBitmap(HybridBinarizer(source)), hints).text
        } catch (_: NotFoundException) {
            null
        } catch (_: ReaderException) {
            null // checksum/format errors on a blurry frame: just try the next frame
        } finally {
            reader.reset()
        }
    }
}
