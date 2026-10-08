package com.privateprotection.mobile.core;

import org.junit.After;
import org.junit.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Tests for BoundedWorkerExecutor: thread limits, queue capacity backpressure,
 * dynamic concurrency throttling, and deterministic shutdown.
 */
public class BoundedWorkerExecutorTest {
    private BoundedWorkerExecutor executor;

    @After
    public void tearDown() {
        if (executor != null && !executor.isShutdown()) {
            executor.shutdownNow();
        }
    }

    @Test
    public void testTaskExecutionOnWorkerThread() throws Exception {
        executor = new BoundedWorkerExecutor(2, 2, 10);
        CountDownLatch latch = new CountDownLatch(1);
        AtomicBoolean ranOnWorker = new AtomicBoolean(false);

        executor.execute(() -> {
            String name = Thread.currentThread().getName();
            if (name.startsWith("pp-sec-worker-")) {
                ranOnWorker.set(true);
            }
            latch.countDown();
        });

        assertTrue(latch.await(2, TimeUnit.SECONDS));
        assertTrue(ranOnWorker.get());
    }

    @Test(expected = RejectedExecutionException.class)
    public void testBoundedQueueBackpressureRejection() throws Exception {
        // Small pool (1 worker) and tiny queue (2 capacity) -> 4th task must be rejected
        executor = new BoundedWorkerExecutor(1, 1, 2);
        CountDownLatch blocker = new CountDownLatch(1);

        // Task 1: occupies the single worker
        executor.execute(() -> {
            try {
                blocker.await(3, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {}
        });

        // Task 2: occupies queue slot 1
        executor.execute(() -> {});

        // Task 3: occupies queue slot 2
        executor.execute(() -> {});

        try {
            // Task 4: exceeds capacity (1 active + 2 queued = 3 max), must throw RejectedExecutionException
            executor.execute(() -> {});
        } finally {
            blocker.countDown();
        }
    }

    @Test
    public void testDynamicConcurrencyThrottling() {
        executor = new BoundedWorkerExecutor(4, 4, 10);
        assertEquals(4, executor.getMaximumPoolSize());

        // Low memory throttle to 1
        executor.throttleConcurrency(1);
        assertEquals(1, executor.getMaximumPoolSize());

        // Restore concurrency
        executor.restoreConcurrency();
        assertEquals(4, executor.getMaximumPoolSize());
    }

    @Test
    public void testGracefulShutdown() throws Exception {
        executor = new BoundedWorkerExecutor(2, 2, 10);
        CountDownLatch latch = new CountDownLatch(2);

        executor.execute(latch::countDown);
        executor.execute(latch::countDown);

        executor.shutdown();
        assertTrue(executor.isShutdown());
        assertTrue(latch.await(2, TimeUnit.SECONDS));
        assertTrue(executor.awaitTermination(2, TimeUnit.SECONDS));
    }

    @Test(expected = RejectedExecutionException.class)
    public void testRejectExecutionAfterShutdown() {
        executor = new BoundedWorkerExecutor(2, 2, 10);
        executor.shutdown();
        executor.execute(() -> {});
    }

    @Test
    public void testShutdownNowInterruptsWorkers() throws Exception {
        executor = new BoundedWorkerExecutor(2, 2, 10);
        CountDownLatch started = new CountDownLatch(1);
        AtomicBoolean wasInterrupted = new AtomicBoolean(false);

        executor.execute(() -> {
            started.countDown();
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                wasInterrupted.set(true);
            }
        });

        assertTrue(started.await(2, TimeUnit.SECONDS));
        executor.shutdownNow();

        // Give worker thread a moment to handle interrupt
        Thread.sleep(100);
        assertTrue(wasInterrupted.get());
    }
}
