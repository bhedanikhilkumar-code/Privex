package com.privateprotection.mobile.shield;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * Immutable canonical descriptor representing an inspected file on Android.
 * Contains truth-first attributes: URI, display name, extension, detected magic MIME,
 * size, timestamp, SHA-256 digest, and source collection.
 */
public class CanonicalFileIdentity {
    private final String uriString;
    private final String fileName;
    private final String fileExtension;
    private final String detectedMimeType;
    private final long sizeBytes;
    private final long lastModifiedMs;
    private final String sha256;
    private final String sourceCollection;
    private final boolean isExecutable;

    public CanonicalFileIdentity(
            String uriString,
            String fileName,
            String fileExtension,
            String detectedMimeType,
            long sizeBytes,
            long lastModifiedMs,
            String sha256,
            String sourceCollection,
            boolean isExecutable
    ) {
        this.uriString = uriString != null ? uriString : "";
        this.fileName = fileName != null ? fileName : "";
        this.fileExtension = fileExtension != null ? fileExtension.toLowerCase() : "";
        this.detectedMimeType = detectedMimeType != null ? detectedMimeType : "application/octet-stream";
        this.sizeBytes = sizeBytes;
        this.lastModifiedMs = lastModifiedMs;
        this.sha256 = sha256 != null ? sha256 : "";
        this.sourceCollection = sourceCollection != null ? sourceCollection : "UNKNOWN";
        this.isExecutable = isExecutable;
    }

    public String getUriString() {
        return uriString;
    }

    public String getFileName() {
        return fileName;
    }

    public String getFileExtension() {
        return fileExtension;
    }

    public String getDetectedMimeType() {
        return detectedMimeType;
    }

    public long getSizeBytes() {
        return sizeBytes;
    }

    public long getLastModifiedMs() {
        return lastModifiedMs;
    }

    public String getSha256() {
        return sha256;
    }

    public String getSourceCollection() {
        return sourceCollection;
    }

    public boolean isExecutable() {
        return isExecutable;
    }

    public JSONObject toJSON() {
        JSONObject obj = new JSONObject();
        try {
            obj.put("uriString", uriString);
            obj.put("fileName", fileName);
            obj.put("fileExtension", fileExtension);
            obj.put("detectedMimeType", detectedMimeType);
            obj.put("sizeBytes", sizeBytes);
            obj.put("lastModifiedMs", lastModifiedMs);
            obj.put("sha256", sha256);
            obj.put("sourceCollection", sourceCollection);
            obj.put("isExecutable", isExecutable);
        } catch (JSONException ignored) {}
        return obj;
    }
}
