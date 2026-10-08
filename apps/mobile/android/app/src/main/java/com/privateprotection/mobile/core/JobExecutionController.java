package com.privateprotection.mobile.core;

/**
 * Controller passed to security workers to support progress reporting,
 * cooperative cancellation checks, and runtime telemetry updates.
 */
public interface JobExecutionController {
    /**
     * Checks if cancellation has been requested for this job.
     */
    boolean isCancellationRequested();

    /**
     * Cooperatively checks for cancellation, throwing JobCancellationException if cancelled.
     */
    void checkCancellation() throws JobCancellationException;

    /**
     * Updates job progress in the range [0.0f, 1.0f].
     */
    void updateProgress(float progress);

    /**
     * Attaches dynamic metadata to the executing job.
     */
    void setMetadata(String key, Object value);
}
