package com.privateprotection.mobile.core;

import android.os.Process;
import android.util.Log;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Bounded Native Worker Executor for Privex Android (Phase T1).
 *
 * Guarantees:
 * 1. Bounded thread count (prevents thread exhaustion & battery drain).
 * 2. Bounded work queue (prevents unbounded memory growth / OOM).
 * 3. Priority set to THREAD_PRIORITY_BACKGROUND.
 * 4. Deterministic shutdown with interruption support.
 * 5. Dynamic concurrency throttling for low-memory & thermal states.
 */
public class BoundedWorkerExecutor {
    private static final String TAG = "BoundedWorkerExecutor";
    public static final int DEFAULT_QUEUE_CAPACITY = 256;
    public static final long KEEP_ALIVE_SECONDS = 60L;

    private final int defaultCoreThreads;
    private final int defaultMaxThreads;
    private final ThreadPoolExecutor executor;
    private final AtomicInteger threadSequence = new AtomicInteger(1);

    public BoundedWorkerExecutor() {
        this(
                Math.max(2, Math.min(4, Runtime.getRuntime().availableProcessors())),
                Math.max(2, Math.min(4, Runtime.getRuntime().availableProcessors())),
                DEFAULT_QUEUE_CAPACITY
        );
    }

    public BoundedWorkerExecutor(int corePoolSize, int maxPoolSize, int queueCapacity) {
        this.defaultCoreThreads = Math.max(1, corePoolSize);
        this.defaultMaxThreads = Math.max(this.defaultCoreThreads, maxPoolSize);

        ThreadFactory threadFactory = r -> {
            Thread t = new Thread(() -> {
                // Set native Linux thread priority to background
                try {
                    Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND);
                } catch (Throwable ignored) {
                }
                r.run();
            }, "pp-sec-worker-" + threadSequence.getAndIncrement());
            t.setDaemon(true);
            return t;
        };

        RejectedExecutionHandler rejectionHandler = (r, executor) -> {
            String msg = "Security worker queue capacity exceeded (" + queueCapacity + " items). System under backpressure.";
            Log.w(TAG, msg);
            throw new RejectedExecutionException(msg);
        };

        this.executor = new ThreadPoolExecutor(
                this.defaultCoreThreads,
                this.defaultMaxThreads,
                KEEP_ALIVE_SECONDS,
                TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(queueCapacity),
                threadFactory,
                rejectionHandler
        );
        this.executor.allowCoreThreadTimeOut(true);
    }

    public void execute(Runnable command) {
        if (command == null) {
            throw new IllegalArgumentException("Runnable command cannot be null");
        }
        executor.execute(command);
    }

    public Future<?> submit(Runnable command) {
        if (command == null) {
            throw new IllegalArgumentException("Runnable command cannot be null");
        }
        return executor.submit(command);
    }

    /**
     * Throttles the thread pool concurrency down to a lower limit (e.g. 1 thread)
     * during low-memory or thermal alerts.
     */
    public synchronized void throttleConcurrency(int targetMaxThreads) {
        int bounded = Math.max(1, Math.min(targetMaxThreads, defaultMaxThreads));
        executor.setCorePoolSize(bounded);
        executor.setMaximumPoolSize(bounded);
        Log.i(TAG, "Throttled worker executor concurrency to " + bounded + " threads.");
    }

    /**
     * Restores default worker concurrency after recovery from low-memory or thermal state.
     */
    public synchronized void restoreConcurrency() {
        executor.setMaximumPoolSize(defaultMaxThreads);
        executor.setCorePoolSize(defaultCoreThreads);
        Log.i(TAG, "Restored worker executor concurrency to " + defaultMaxThreads + " threads.");
    }

    public int getActiveCount() {
        return executor.getActiveCount();
    }

    public int getQueueSize() {
        return executor.getQueue().size();
    }

    public int getPoolSize() {
        return executor.getPoolSize();
    }

    public int getMaximumPoolSize() {
        return executor.getMaximumPoolSize();
    }

    public boolean isShutdown() {
        return executor.isShutdown();
    }

    public boolean isTerminated() {
        return executor.isTerminated();
    }

    public void shutdown() {
        Log.i(TAG, "Initiating graceful shutdown of security worker executor.");
        executor.shutdown();
    }

    public void shutdownNow() {
        Log.w(TAG, "Executing immediate shutdownNow of security worker executor.");
        executor.shutdownNow();
    }

    public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
        return executor.awaitTermination(timeout, unit);
    }
}
