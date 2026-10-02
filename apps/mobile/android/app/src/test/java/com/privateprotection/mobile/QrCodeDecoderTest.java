package com.privateprotection.mobile;

import android.graphics.Bitmap;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.util.EnumMap;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Unit tests for QrCodeDecoder.
 * Verifies real computer vision QR decoding, error handling, and payload extraction.
 */
public class QrCodeDecoderTest {

    @Test
    public void testDecodeNullAndEmptyInputsReturnNull() {
        assertNull("Null input should return null", QrCodeDecoder.decodeBase64Image(null));
        assertNull("Empty input should return null", QrCodeDecoder.decodeBase64Image(""));
        assertNull("Whitespace input should return null", QrCodeDecoder.decodeBase64Image("   "));
        assertNull("Invalid base64 should return null", QrCodeDecoder.decodeBase64Image("not-valid-base64!"));
        assertNull("Null bitmap should return null", QrCodeDecoder.decodeBitmap(null));
        assertNull("Null pixels should return null", QrCodeDecoder.decodeRgbPixels(null, 0, 0));
        assertNull("Zero dimensions should return null", QrCodeDecoder.decodeRgbPixels(new int[10], 0, 0));
    }

    @Test
    public void testDecodeRgbPixelsWithSynthesizedQrCode() throws Exception {
        String testPayload = "https://privateprotection.org/verify";

        QRCodeWriter writer = new QRCodeWriter();
        Map<EncodeHintType, Object> hints = new EnumMap<>(EncodeHintType.class);
        hints.put(EncodeHintType.CHARACTER_SET, "UTF-8");
        hints.put(EncodeHintType.MARGIN, 2);

        int size = 200;
        BitMatrix bitMatrix = writer.encode(testPayload, BarcodeFormat.QR_CODE, size, size, hints);
        assertNotNull("BitMatrix should be generated", bitMatrix);

        // Convert bit matrix to ARGB pixel array
        int[] pixels = new int[size * size];
        for (int y = 0; y < size; y++) {
            for (int x = 0; x < size; x++) {
                pixels[y * size + x] = bitMatrix.get(x, y) ? 0xFF000000 : 0xFFFFFFFF;
            }
        }

        // Test decoding raw luminance pixels
        String decoded = QrCodeDecoder.decodeRgbPixels(pixels, size, size);
        assertNotNull("Decoder should detect QR barcode", decoded);
        assertEquals("Decoded payload must exactly match input payload", testPayload, decoded);
    }

    @Test
    public void testDecodePhishingUrlQrCode() throws Exception {
        String phishUrl = "http://192.168.1.100/login.php?urgent=true";

        QRCodeWriter writer = new QRCodeWriter();
        int size = 250;
        BitMatrix matrix = writer.encode(phishUrl, BarcodeFormat.QR_CODE, size, size);

        int[] pixels = new int[size * size];
        for (int y = 0; y < size; y++) {
            for (int x = 0; x < size; x++) {
                pixels[y * size + x] = matrix.get(x, y) ? 0xFF000000 : 0xFFFFFFFF;
            }
        }

        String decoded = QrCodeDecoder.decodeRgbPixels(pixels, size, size);
        assertEquals("Phishing URL decoded correctly", phishUrl, decoded);
    }

    @Test
    public void testDecodeScamExtortionQrCode() throws Exception {
        String scamText = "Send 0.5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa within 24 hours";

        QRCodeWriter writer = new QRCodeWriter();
        int size = 300;
        BitMatrix matrix = writer.encode(scamText, BarcodeFormat.QR_CODE, size, size);

        int[] pixels = new int[size * size];
        for (int y = 0; y < size; y++) {
            for (int x = 0; x < size; x++) {
                pixels[y * size + x] = matrix.get(x, y) ? 0xFF000000 : 0xFFFFFFFF;
            }
        }

        String decoded = QrCodeDecoder.decodeRgbPixels(pixels, size, size);
        assertEquals("Scam extortion text decoded correctly", scamText, decoded);
    }

    @Test
    public void testDecodeNoisePixelsReturnsNullSafely() {
        int size = 100;
        int[] noisePixels = new int[size * size];
        // Fill with random noise
        for (int i = 0; i < noisePixels.length; i++) {
            noisePixels[i] = (i % 2 == 0) ? 0xFFFFFFFF : 0xFF000000;
        }

        String decoded = QrCodeDecoder.decodeRgbPixels(noisePixels, size, size);
        assertNull("Noise image should not decode to a QR code", decoded);
    }
}
