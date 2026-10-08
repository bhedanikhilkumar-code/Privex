package com.privateprotection.mobile.core;

import org.json.JSONObject;

/**
 * Functional interface for a security worker executable task.
 * Runs strictly on background worker threads, never on the Android main/UI thread.
 */
@FunctionalInterface
public interface SecurityWorkerTask {
    /**
     * Executes the security job logic.
     *
     * @param job The security job descriptor
     * @param controller Execution controller for progress and cancellation
     * @return Execution result payload
     * @throws Exception if job fails or is cancelled
     */
    JSONObject execute(SecurityJob job, JobExecutionController controller) throws Exception;
}
