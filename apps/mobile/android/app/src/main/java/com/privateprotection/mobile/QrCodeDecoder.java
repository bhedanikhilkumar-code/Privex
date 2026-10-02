package com.privateprotection.mobile;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.util.Base64;
import android.util.Log;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.NotFoundException;
import com.google.zxing.RGBLuminanceSource;
import com.google.zxing.Result;
import com.google.zxing.common.HybridBinarizer;

import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;

/**
 * QrCodeDecoder: Computer Vision QR barcode decoder powered by ZXing.
 * 
 * Executes 100% on-device in volatile memory.
 * Decodes camera video frames, base64 image captures, and raw luminance arrays.
 */
public class QrCodeDecoder {
    private static final String TAG = "QrCodeDecoder";

    private static final Map<DecodeHintType, Object> HINTS = new EnumMap<>(DecodeHintType.class);

    static {
        HINTS.put(DecodeHintType.POSSIBLE_FORMATS, EnumSet.of(BarcodeFormat.QR_CODE));
        HINTS.put(DecodeHintType.TRY_HARDER, Boolean.TRUE);
        HINTS.put(DecodeHintType.CHARACTER_SET, "UTF-8");
    }

    /**
     * Decodes a QR code from a Base64-encoded image string (PNG, JPEG, WebP).
     * Accepts data URI prefixes (e.g., "data:image/jpeg;base64,...") or raw base64.
     * 
     * @param base64Image Untrusted base64 string
     * @return Decoded payload text, or null if no QR code found
     */
    public static String decodeBase64Image(String base64Image) {
        if (base64Image == null || base64Image.trim().isEmpty()) {
            return null;
        }

        try {
            String cleanBase64 = base64Image.trim();
            int commaIdx = cleanBase64.indexOf(",");
            if (commaIdx >= 0) {
                cleanBase64 = cleanBase64.substring(commaIdx + 1);
            }

            byte[] imageBytes;
            try {
                imageBytes = java.util.Base64.getDecoder().decode(cleanBase64);
            } catch (Exception ex) {
                try {
                    imageBytes = Base64.decode(cleanBase64, Base64.DEFAULT);
                } catch (Throwable t) {
                    return null;
                }
            }

            Bitmap bitmap = BitmapFactory.decodeByteArray(imageBytes, 0, imageBytes.length);
            if (bitmap == null) {
                return null;
            }

            return decodeBitmap(bitmap);
        } catch (Exception e) {
            Log.w(TAG, "Error decoding QR image from base64: " + e.getMessage());
            return null;
        }
    }

    /**
     * Decodes a QR code directly from an Android Bitmap.
     */
    public static String decodeBitmap(Bitmap bitmap) {
        if (bitmap == null) return null;

        int width = bitmap.getWidth();
        int height = bitmap.getHeight();
        int[] pixels = new int[width * height];
        bitmap.getPixels(pixels, 0, width, 0, 0, width, height);

        return decodeRgbPixels(pixels, width, height);
    }

    /**
     * Decodes a QR code from raw ARGB/RGB pixel array and dimensions.
     */
    public static String decodeRgbPixels(int[] pixels, int width, int height) {
        if (pixels == null || width <= 0 || height <= 0) return null;

        try {
            RGBLuminanceSource source = new RGBLuminanceSource(width, height, pixels);
            BinaryBitmap binaryBitmap = new BinaryBitmap(new HybridBinarizer(source));

            MultiFormatReader reader = new MultiFormatReader();
            reader.setHints(HINTS);

            Result result = reader.decodeWithState(binaryBitmap);
            return result != null ? result.getText() : null;
        } catch (NotFoundException e) {
            // No barcode detected in frame (normal during viewfinder polling)
            return null;
        } catch (Exception e) {
            Log.w(TAG, "Decoder exception: " + e.getMessage());
            return null;
        }
    }
}
