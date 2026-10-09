package com.privateprotection.mobile.core;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Canonical Security Job Model for Privex Android (Phase T1).
 *
 * Encapsulates job metadata, thread-safe atomic state transitions,
 * progress tracking, cancellation tracking, and JSON serialization.
 */
public class SecurityJob {
    private final String id;
    private final JobType type;
    private final long createdAtMs;
    private volatile long startedAtMs;
    private volatile long completedAtMs;

    private final AtomicReference<JobState> state;
    private final AtomicReference<Float> progress;

    private volatile String cancellationReason;
    private volatile String errorReason;
    private volatile JSONObject metadata;
    private volatile JSONObject result;

    public SecurityJob(JobType type, JSONObject metadata) {
        this(UUID.randomUUID().toString(), type, System.currentTimeMillis(), metadata);
    }

    public SecurityJob(String id, JobType type, long createdAtMs, JSONObject metadata) {
        this.id = id != null ? id : UUID.randomUUID().toString();
        this.type = type != null ? type : JobType.HEALTH_CHECK;
        this.createdAtMs = createdAtMs;
        this.startedAtMs = 0L;
        this.completedAtMs = 0L;
        this.state = new AtomicReference<>(JobState.QUEUED);
        this.progress = new AtomicReference<>(0.0f);
        this.cancellationReason = null;
        this.errorReason = null;
        this.metadata = metadata != null ? metadata : new JSONObject();
        this.result = null;
    }

    public String getId() {
        return id;
    }

    public JobType getType() {
        return type;
    }

    public long getCreatedAtMs() {
        return createdAtMs;
    }

    public long getStartedAtMs() {
        return startedAtMs;
    }

    public void setStartedAtMs(long startedAtMs) {
        this.startedAtMs = startedAtMs;
    }

    public long getCompletedAtMs() {
        return completedAtMs;
    }

    public void setCompletedAtMs(long completedAtMs) {
        this.completedAtMs = completedAtMs;
    }

    public JobState getState() {
        return state.get();
    }

    /**
     * Atomically transitions job to the target state if the transition is valid according
     * to JobState transition rules.
     *
     * @param next Target state
     * @param reason Optional detail/reason for transition
     * @return true if transition succeeded, false if rejected
     */
    public synchronized boolean transitionTo(JobState next, String reason) {
        if (next == null) return false;
        JobState current = state.get();
        if (current == next) return true;

        if (!current.canTransitionTo(next)) {
            return false;
        }

        if (next == JobState.RUNNING && startedAtMs == 0L) {
            startedAtMs = System.currentTimeMillis();
        } else if (next.isTerminal() && completedAtMs == 0L) {
            completedAtMs = System.currentTimeMillis();
        }

        if (next == JobState.CANCELLING || next == JobState.CANCELLED || next == JobState.DEFERRED || next == JobState.PARTIAL) {
            if (reason != null && !reason.trim().isEmpty()) {
                this.cancellationReason = reason;
            }
        } else if (next == JobState.FAILED) {
            if (reason != null && !reason.trim().isEmpty()) {
                this.errorReason = reason;
            }
        }

        state.set(next);
        return true;
    }

    public float getProgress() {
        return progress.get();
    }

    public void setProgress(float value) {
        float clamped = Math.max(0.0f, Math.min(1.0f, value));
        progress.set(clamped);
    }

    public boolean isCancelled() {
        JobState s = state.get();
        return s == JobState.CANCELLING || s == JobState.CANCELLED;
    }

    public boolean isTerminal() {
        return state.get().isTerminal();
    }

    public String getCancellationReason() {
        return cancellationReason;
    }

    public void setCancellationReason(String cancellationReason) {
        this.cancellationReason = cancellationReason;
    }

    public String getErrorReason() {
        return errorReason;
    }

    public void setErrorReason(String errorReason) {
        this.errorReason = errorReason;
    }

    public JSONObject getMetadata() {
        return metadata;
    }

    public synchronized void setMetadata(JSONObject metadata) {
        this.metadata = metadata != null ? metadata : new JSONObject();
    }

    public synchronized void putMetadata(String key, Object value) {
        if (key == null) return;
        try {
            if (this.metadata == null) {
                this.metadata = new JSONObject();
            }
            this.metadata.put(key, value);
        } catch (JSONException ignored) {
        }
    }

    public JSONObject getResult() {
        return result;
    }

    public synchronized void setResult(JSONObject result) {
        this.result = result;
    }

    public JSONObject toJSON() {
        JSONObject obj = new JSONObject();
        try {
            obj.put("id", id);
            obj.put("type", type.name());
            obj.put("state", state.get().name());
            obj.put("progress", (double) progress.get());
            obj.put("createdAtMs", createdAtMs);
            obj.put("startedAtMs", startedAtMs);
            obj.put("completedAtMs", completedAtMs);
            if (cancellationReason != null) obj.put("cancellationReason", cancellationReason);
            if (errorReason != null) obj.put("errorReason", errorReason);
            if (metadata != null) obj.put("metadata", metadata);
            if (result != null) obj.put("result", result);
        } catch (JSONException ignored) {
        }
        return obj;
    }

    public static SecurityJob fromJSON(JSONObject obj) {
        if (obj == null) return null;
        try {
            String id = obj.optString("id", UUID.randomUUID().toString());
            JobType type = JobType.fromString(obj.optString("type", "HEALTH_CHECK"));
            long createdAt = obj.optLong("createdAtMs", System.currentTimeMillis());
            JSONObject metadata = obj.optJSONObject("metadata");

            SecurityJob job = new SecurityJob(id, type, createdAt, metadata);
            job.startedAtMs = obj.optLong("startedAtMs", 0L);
            job.completedAtMs = obj.optLong("completedAtMs", 0L);
            job.progress.set((float) obj.optDouble("progress", 0.0));
            job.cancellationReason = obj.optString("cancellationReason", null);
            job.errorReason = obj.optString("errorReason", null);
            job.result = obj.optJSONObject("result");

            String stateStr = obj.optString("state", "QUEUED");
            try {
                JobState s = JobState.valueOf(stateStr);
                job.state.set(s);
            } catch (Exception e) {
                job.state.set(JobState.FAILED);
            }

            return job;
        } catch (Exception e) {
            return null;
        }
    }
}
