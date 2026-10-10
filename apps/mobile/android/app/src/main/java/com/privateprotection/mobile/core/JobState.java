package com.privateprotection.mobile.core;

/**
 * Deterministic lifecycle states for native mobile security jobs (Phase T1).
 *
 * States are strictly ordered and unidirectional:
 * QUEUED -> RUNNING -> COMPLETED / FAILED / CANCELLING -> CANCELLED
 */
public enum JobState {
    QUEUED,
    RUNNING,
    THROTTLED,
    DEFERRED,
    PARTIAL,
    CANCELLING,
    CANCELLED,
    COMPLETED,
    FAILED;

    public boolean isTerminal() {
        return this == CANCELLED || this == COMPLETED || this == FAILED || this == DEFERRED || this == PARTIAL;
    }

    public boolean canTransitionTo(JobState next) {
        if (next == null) return false;
        if (this == next) return true;
        if (isTerminal()) return false; // Terminal states cannot transition further

        switch (this) {
            case QUEUED:
                return next == RUNNING || next == THROTTLED || next == DEFERRED || next == CANCELLING || next == CANCELLED || next == FAILED;
            case RUNNING:
                return next == THROTTLED || next == PARTIAL || next == CANCELLING || next == CANCELLED || next == COMPLETED || next == FAILED;
            case THROTTLED:
                return next == RUNNING || next == PARTIAL || next == CANCELLING || next == CANCELLED || next == COMPLETED || next == FAILED;
            case CANCELLING:
                return next == CANCELLED || next == FAILED;
            default:
                return false;
        }
    }
}
