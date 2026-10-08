package com.privateprotection.mobile.core;

/**
 * Thrown when a running security job is cancelled by user request or system shutdown.
 */
public class JobCancellationException extends Exception {
    private final String jobId;
    private final String reason;

    public JobCancellationException(String jobId, String reason) {
        super("Job " + jobId + " was cancelled: " + reason);
        this.jobId = jobId;
        this.reason = reason;
    }

    public String getJobId() {
        return jobId;
    }

    public String getReason() {
        return reason;
    }
}
