package com.privateprotection.mobile.core;

/**
 * Canonical job types for native mobile security operations (Phase T1).
 * Serves as the registration contract for upcoming T2-T13 security subsystems.
 */
public enum JobType {
    FILE_SCAN,
    URL_SCAN,
    PACKAGE_AUDIT,
    DOWNLOAD_INSPECT,
    STORAGE_SCAN,
    HEALTH_CHECK,
    MAINTENANCE;

    public static JobType fromString(String raw) {
        if (raw == null || raw.trim().isEmpty()) {
            return HEALTH_CHECK;
        }
        try {
            return JobType.valueOf(raw.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return HEALTH_CHECK;
        }
    }
}
