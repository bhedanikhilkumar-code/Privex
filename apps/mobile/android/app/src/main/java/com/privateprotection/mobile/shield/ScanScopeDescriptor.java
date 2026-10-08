package com.privateprotection.mobile.shield;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * ScanScopeDescriptor: Canonical representation of a storage or application scope (Phase T4).
 *
 * Truthful Android Scopes:
 * - MEDIASTORE_DOWNLOADS: MediaStore.Downloads (API 29+) or external downloads
 * - MEDIASTORE_IMAGES: MediaStore.Images
 * - MEDIASTORE_VIDEO: MediaStore.Video
 * - MEDIASTORE_AUDIO: MediaStore.Audio
 * - MEDIASTORE_FILES: MediaStore.Files
 * - SAF_TREE: User-granted persistent directory via ACTION_OPEN_DOCUMENT_TREE
 * - INSTALLED_PACKAGES: Applications inspected via PackageManager
 * - APP_QUARANTINE_VAULT: Private quarantine evidence storage
 * - RESTRICTED_SYSTEM: /data/data/* and system private dirs (truthfully marked INACCESSIBLE/PERMISSION_DENIED)
 */
public class ScanScopeDescriptor {
    public enum ScopeType {
        MEDIASTORE_DOWNLOADS,
        MEDIASTORE_IMAGES,
        MEDIASTORE_VIDEO,
        MEDIASTORE_AUDIO,
        MEDIASTORE_FILES,
        SAF_TREE,
        INSTALLED_PACKAGES,
        APP_QUARANTINE_VAULT,
        RESTRICTED_SYSTEM
    }

    public enum AccessibilityState {
        AUTOMATICALLY_ACCESSIBLE,
        MEDIASTORE_ACCESSIBLE,
        SAF_USER_GRANTED,
        APP_PRIVATE,
        INACCESSIBLE,
        PERMISSION_DENIED
    }

    public enum ScopeScanStatus {
        PENDING,
        SCANNING,
        COMPLETED,
        PARTIAL,
        SKIPPED,
        PERMISSION_DENIED,
        FAILED,
        CANCELLED
    }

    private final String scopeId;
    private final String displayName;
    private final ScopeType scopeType;
    private final String uriOrPath;
    private final AccessibilityState accessibilityState;
    private ScopeScanStatus scanStatus;

    private int filesDiscovered = 0;
    private int filesScanned = 0;
    private int filesSkipped = 0;
    private int threatsFound = 0;
    private long startTimeMs = 0;
    private long endTimeMs = 0;
    private String errorDetails = null;

    public ScanScopeDescriptor(
            String scopeId,
            String displayName,
            ScopeType scopeType,
            String uriOrPath,
            AccessibilityState accessibilityState
    ) {
        this.scopeId = scopeId;
        this.displayName = displayName;
        this.scopeType = scopeType;
        this.uriOrPath = uriOrPath != null ? uriOrPath : "";
        this.accessibilityState = accessibilityState;
        this.scanStatus = ScopeScanStatus.PENDING;
    }

    public String getScopeId() { return scopeId; }
    public String getDisplayName() { return displayName; }
    public ScopeType getScopeType() { return scopeType; }
    public String getUriOrPath() { return uriOrPath; }
    public AccessibilityState getAccessibilityState() { return accessibilityState; }
    public ScopeScanStatus getScanStatus() { return scanStatus; }

    public void setScanStatus(ScopeScanStatus status) { this.scanStatus = status; }
    public int getFilesDiscovered() { return filesDiscovered; }
    public void setFilesDiscovered(int count) { this.filesDiscovered = count; }
    public void incrementDiscovered() { this.filesDiscovered++; }

    public int getFilesScanned() { return filesScanned; }
    public void incrementScanned() { this.filesScanned++; }

    public int getFilesSkipped() { return filesSkipped; }
    public void incrementSkipped() { this.filesSkipped++; }

    public int getThreatsFound() { return threatsFound; }
    public void incrementThreats() { this.threatsFound++; }

    public long getStartTimeMs() { return startTimeMs; }
    public void setStartTimeMs(long time) { this.startTimeMs = time; }

    public long getEndTimeMs() { return endTimeMs; }
    public void setEndTimeMs(long time) { this.endTimeMs = time; }

    public String getErrorDetails() { return errorDetails; }
    public void setErrorDetails(String err) { this.errorDetails = err; }

    public JSONObject toJSON() {
        JSONObject obj = new JSONObject();
        try {
            obj.put("scopeId", scopeId);
            obj.put("displayName", displayName);
            obj.put("scopeType", scopeType.name());
            obj.put("uriOrPath", uriOrPath);
            obj.put("accessibilityState", accessibilityState.name());
            obj.put("scanStatus", scanStatus.name());
            obj.put("filesDiscovered", filesDiscovered);
            obj.put("filesScanned", filesScanned);
            obj.put("filesSkipped", filesSkipped);
            obj.put("threatsFound", threatsFound);
            obj.put("startTimeMs", startTimeMs);
            obj.put("endTimeMs", endTimeMs);
            if (errorDetails != null) {
                obj.put("errorDetails", errorDetails);
            }
        } catch (JSONException ignored) {}
        return obj;
    }
}
