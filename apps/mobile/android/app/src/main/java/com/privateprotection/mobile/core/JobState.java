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
    CANCELLING,
    CANCELLED,
    COMPLETED,
    FAILED;

    public boolean isTerminal() {
        return this == CANCELLED || this == COMPLETED || this == FAILED;
    }

    public boolean canTransitionTo(JobState next) {
        if (next == null) return false;
        if (this == next) return true;
        if (isTerminal()) return false; // Terminal states cannot transition further

        switch (this) {
            case QUEUED:
                return next == RUNNING || next == CANCELLING || next == CANCELLED || next == FAILED;
            case RUNNING:
                return next == CANCELLING || next == CANCELLED || next == COMPLETED || next == FAILED;
            case CANCELLING:
                return next == CANCELLED || next == FAILED;
            default:
                return false;
        }
    }
}
