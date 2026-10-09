package com.privateprotection.mobile.core;

import android.content.ComponentCallbacks2;
import android.content.Context;
import android.os.Looper;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * MobileSecurityCoordinator: The central native execution coordinator for Privex Android (Phase T1).
 *
 * Responsibilities:
 * - Thread-safe security worker coordination
 * - Bounded background execution off the Android UI thread
 * - Deterministic job lifecycle management (QUEUED -> RUNNING -> COMPLETED / FAILED / CANCELLED)
 * - Cooperative job cancellation
 * - Truthful process-death recovery via JobStateStore
 * - Low-memory and thermal concurrency throttling
 * - Integration anchor for upcoming security shields (T2-T13)
 * - Strictly zero detection algorithms (delegates to shared security engine)
 */
public class MobileSecurityCoordinator {
    private static final String TAG = "MobileSecurityCoord";
    private static volatile MobileSecurityCoordinator sInstance = null;

    private final Context appContext;
    private final BoundedWorkerExecutor workerExecutor;
    private final JobStateStore stateStore;

    private final Map<String, SecurityJob> activeJobs = new ConcurrentHashMap<>();
    private final Map<String, Future<?>> runningFutures = new ConcurrentHashMap<>();

    private final AtomicBoolean isShutdown = new AtomicBoolean(false);
    private final AtomicBoolean isThrottled = new AtomicBoolean(false);
    private final AdaptiveResourceManager adaptiveManager;

    public static MobileSecurityCoordinator getInstance(Context context) {
        if (sInstance == null) {
            synchronized (MobileSecurityCoordinator.class) {
                if (sInstance == null) {
                    sInstance = new MobileSecurityCoordinator(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    /**
     * Resets the singleton instance (used in unit testing).
     */
    public static synchronized void resetInstance() {
        if (sInstance != null) {
            sInstance.shutdown();
            sInstance = null;
        }
    }

    /**
     * Sets the singleton instance (used in unit testing).
     */
    public static synchronized void setInstanceForTest(MobileSecurityCoordinator instance) {
        sInstance = instance;
    }

    public MobileSecurityCoordinator(Context context) {
        this(context, new BoundedWorkerExecutor(), new JobStateStore(context));
    }

    public MobileSecurityCoordinator(Context context, BoundedWorkerExecutor executor, JobStateStore store) {
        this.appContext = context.getApplicationContext();
        this.workerExecutor = executor;
        this.stateStore = store;
        this.adaptiveManager = AdaptiveResourceManager.getInstance(this.appContext);

        // Listen for adaptive mode changes
        this.adaptiveManager.addListener((newMode, reason) -> {
            applyAdaptiveConcurrency(newMode);
        });
        applyAdaptiveConcurrency(this.adaptiveManager.getCurrentMode());

        // Perform truthful process recovery on coordinator startup
        List<SecurityJob> recovered = this.stateStore.recoverOrphanedJobs();
        if (!recovered.isEmpty()) {
            Log.w(TAG, "Truthful crash recovery: updated " + recovered.size() + " orphaned jobs to FAILED.");
        }
        Log.i(TAG, "MobileSecurityCoordinator initialized successfully.");
    }

    private void applyAdaptiveConcurrency(AdaptiveResourceManager.ResourceMode mode) {
        int recommended = adaptiveManager.getRecommendedWorkerConcurrency(workerExecutor.getDefaultMaxThreads());
        if (mode == AdaptiveResourceManager.ResourceMode.NORMAL) {
            workerExecutor.restoreConcurrency();
            isThrottled.set(false);
        } else {
            workerExecutor.throttleConcurrency(recommended);
            isThrottled.set(true);
        }
    }

    /**
     * Submits a security job to the bounded background worker executor.
     * Guaranteed never to execute on the Android main/UI thread.
     *
     * @param type The security job type
     * @param metadata Optional metadata payload
     * @param task The executable task
     * @return The created SecurityJob handle
     */
    public SecurityJob submitJob(JobType type, JSONObject metadata, SecurityWorkerTask task) {
        if (isShutdown.get()) {
            throw new IllegalStateException("MobileSecurityCoordinator has been shut down");
        }
        if (type == null) {
            throw new IllegalArgumentException("JobType cannot be null");
        }
        if (task == null) {
            throw new IllegalArgumentException("SecurityWorkerTask cannot be null");
        }

        SecurityJob job = new SecurityJob(type, metadata);

        // Check if job is a non-critical scheduled scan that must be deferred
        boolean isScheduled = metadata != null && metadata.optBoolean("isScheduled", false);
        if (isScheduled && type == JobType.STORAGE_SCAN && !adaptiveManager.canExecuteScheduledDeepScan()) {
            String deferReason = "Deferred due to adaptive resource constraints: " + adaptiveManager.getTransitionReason();
            Log.w(TAG, "Deferring scheduled job " + job.getId() + " - " + deferReason);
            job.transitionTo(JobState.DEFERRED, deferReason);
            stateStore.persistJob(job);
            return job;
        }

        activeJobs.put(job.getId(), job);
        stateStore.persistJob(job);

        try {
            Future<?> future = workerExecutor.submit(() -> runWorkerTask(job, task));
            runningFutures.put(job.getId(), future);
        } catch (RejectedExecutionException e) {
            job.transitionTo(JobState.FAILED, "System under backpressure: worker queue full");
            activeJobs.remove(job.getId());
            stateStore.persistJob(job);
            throw e;
        }

        return job;
    }

    /**
     * Internal execution wrapper running on a background worker thread.
     */
    private void runWorkerTask(SecurityJob job, SecurityWorkerTask task) {
        // Enforce constitutional invariant: security work NEVER runs on UI thread
        Looper mainLooper = Looper.getMainLooper();
        if (mainLooper != null && Looper.myLooper() == mainLooper) {
            String err = "SECURITY_INVARIANT_VIOLATION: Worker attempted to execute on Android Main Looper";
            Log.e(TAG, err);
            job.transitionTo(JobState.FAILED, err);
            stateStore.persistJob(job);
            activeJobs.remove(job.getId());
            runningFutures.remove(job.getId());
            return;
        }

        // Check if job was cancelled before execution started
        if (job.isCancelled()) {
            Log.i(TAG, "Job " + job.getId() + " was cancelled prior to execution start.");
            job.transitionTo(JobState.CANCELLED, job.getCancellationReason());
            stateStore.persistJob(job);
            activeJobs.remove(job.getId());
            runningFutures.remove(job.getId());
            return;
        }

        boolean started = job.transitionTo(JobState.RUNNING, null);
        if (!started) {
            Log.w(TAG, "Failed to transition job " + job.getId() + " to RUNNING; current state=" + job.getState());
            activeJobs.remove(job.getId());
            runningFutures.remove(job.getId());
            return;
        }
        stateStore.persistJob(job);

        JobExecutionController controller = new JobExecutionController() {
            @Override
            public boolean isCancellationRequested() {
                return job.isCancelled();
            }

            @Override
            public void checkCancellation() throws JobCancellationException {
                if (job.isCancelled()) {
                    throw new JobCancellationException(job.getId(), job.getCancellationReason());
                }
            }

            @Override
            public void updateProgress(float progress) {
                job.setProgress(progress);
            }

            @Override
            public void setMetadata(String key, Object value) {
                job.putMetadata(key, value);
            }
        };

        try {
            JSONObject result = task.execute(job, controller);
            if (job.isCancelled()) {
                job.transitionTo(JobState.CANCELLED, job.getCancellationReason());
            } else {
                job.setResult(result != null ? result : new JSONObject());
                job.setProgress(1.0f);
                job.transitionTo(JobState.COMPLETED, null);
            }
        } catch (JobCancellationException e) {
            Log.i(TAG, "Security job " + job.getId() + " cooperative cancellation confirmed: " + e.getReason());
            job.transitionTo(JobState.CANCELLED, e.getReason());
        } catch (Throwable t) {
            if (job.isCancelled() || t instanceof InterruptedException) {
                String reason = job.getCancellationReason();
                if (reason == null || reason.trim().isEmpty()) {
                    reason = "Cancelled / Thread interrupted";
                }
                Log.i(TAG, "Security job " + job.getId() + " interrupted or cancelled during execution");
                job.transitionTo(JobState.CANCELLED, reason);
            } else {
                String err = t.getMessage() != null ? t.getMessage() : t.getClass().getSimpleName();
                Log.e(TAG, "Security job " + job.getId() + " failed with exception: " + err, t);
                job.transitionTo(JobState.FAILED, err);
            }
        } finally {
            activeJobs.remove(job.getId());
            runningFutures.remove(job.getId());
            stateStore.persistJob(job);
        }
    }

    /**
     * Cancels an active or queued security job.
     *
     * @param jobId ID of the job to cancel
     * @param reason Human-readable reason for cancellation
     * @return true if cancellation was initiated, false if job not found or already terminal
     */
    public boolean cancelJob(String jobId, String reason) {
        if (jobId == null) return false;
        SecurityJob job = activeJobs.get(jobId);
        if (job == null) {
            job = stateStore.getJob(jobId);
        }
        if (job == null || job.isTerminal()) {
            return false;
        }

        String safeReason = (reason != null && !reason.trim().isEmpty()) ? reason.trim() : "Cancelled by user or system";
        boolean transitioned = job.transitionTo(JobState.CANCELLING, safeReason);
        if (!transitioned) {
            return false;
        }

        Future<?> future = runningFutures.get(jobId);
        if (future != null) {
            future.cancel(true);
        }

        // If job was still queued (never started), transition directly to CANCELLED
        if (job.getStartedAtMs() == 0L) {
            job.transitionTo(JobState.CANCELLED, safeReason);
            activeJobs.remove(jobId);
        }

        stateStore.persistJob(job);
        Log.i(TAG, "Cancellation initiated for job " + jobId + " (reason: " + safeReason + ")");
        return true;
    }

    /**
     * Low-memory handler hooked into Android's ComponentCallbacks2.
     * Throttles worker pool to 1 thread when memory pressure is moderate or severe.
     */
    public void onTrimMemory(int level) {
        if (level >= ComponentCallbacks2.TRIM_MEMORY_MODERATE || level >= ComponentCallbacks2.TRIM_MEMORY_RUNNING_LOW) {
            Log.w(TAG, "Received TRIM_MEMORY (" + level + "). Engaging low-memory worker throttling.");
            workerExecutor.throttleConcurrency(1);
            isThrottled.set(true);
        } else if (level <= ComponentCallbacks2.TRIM_MEMORY_RUNNING_MODERATE && isThrottled.get()) {
            Log.i(TAG, "Memory pressure normalized. Restoring worker concurrency.");
            workerExecutor.restoreConcurrency();
            isThrottled.set(false);
        }
    }

    public void onLowMemory() {
        Log.w(TAG, "System broadcast onLowMemory! Throttling security workers to minimal profile.");
        workerExecutor.throttleConcurrency(1);
        isThrottled.set(true);
    }

    public SecurityJob getJob(String jobId) {
        if (jobId == null) return null;
        SecurityJob job = activeJobs.get(jobId);
        if (job != null) return job;
        return stateStore.getJob(jobId);
    }

    public List<SecurityJob> getActiveJobs() {
        return new ArrayList<>(activeJobs.values());
    }

    public List<SecurityJob> getRecentJobs(int limit) {
        List<SecurityJob> all = stateStore.getAllJobs();
        Collections.reverse(all); // most recent first
        int count = Math.min(Math.max(1, limit), all.size());
        return all.subList(0, count);
    }

    public JSONObject getCoordinatorStats() {
        JSONObject obj = new JSONObject();
        try {
            obj.put("isShutdown", isShutdown.get());
            obj.put("isThrottled", isThrottled.get());
            obj.put("activeJobsCount", activeJobs.size());
            obj.put("workerActiveThreads", workerExecutor.getActiveCount());
            obj.put("workerPoolSize", workerExecutor.getPoolSize());
            obj.put("workerMaxPoolSize", workerExecutor.getMaximumPoolSize());
            obj.put("workerQueueSize", workerExecutor.getQueueSize());
            obj.put("totalPersistedJobs", stateStore.getAllJobs().size());
            if (adaptiveManager != null) {
                obj.put("adaptiveStatus", adaptiveManager.getAdaptiveStatusJSON());
            }
        } catch (JSONException ignored) {
        }
        return obj;
    }

    public boolean isShutdown() {
        return isShutdown.get();
    }

    public synchronized void shutdown() {
        if (isShutdown.compareAndSet(false, true)) {
            Log.i(TAG, "Shutting down MobileSecurityCoordinator.");
            // Cancel all active jobs
            for (SecurityJob job : activeJobs.values()) {
                cancelJob(job.getId(), "Coordinator shutdown");
            }
            workerExecutor.shutdown();
        }
    }

    public synchronized void shutdownNow() {
        if (isShutdown.compareAndSet(false, true)) {
            Log.w(TAG, "Executing immediate shutdownNow on MobileSecurityCoordinator.");
            for (SecurityJob job : activeJobs.values()) {
                job.transitionTo(JobState.CANCELLED, "Coordinator immediate shutdown");
                stateStore.persistJob(job);
            }
            activeJobs.clear();
            runningFutures.clear();
            workerExecutor.shutdownNow();
        }
    }

    public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
        return workerExecutor.awaitTermination(timeout, unit);
    }
}
