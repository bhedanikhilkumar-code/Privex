package com.privateprotection.mobile.core;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Tests for JobState deterministic lifecycle states and transition rules (Phase T1).
 */
public class JobStateTest {

    @Test
    public void testTerminalStates() {
        assertFalse(JobState.QUEUED.isTerminal());
        assertFalse(JobState.RUNNING.isTerminal());
        assertFalse(JobState.CANCELLING.isTerminal());

        assertTrue(JobState.CANCELLED.isTerminal());
        assertTrue(JobState.COMPLETED.isTerminal());
        assertTrue(JobState.FAILED.isTerminal());
    }

    @Test
    public void testValidTransitionsFromQueued() {
        assertTrue(JobState.QUEUED.canTransitionTo(JobState.RUNNING));
        assertTrue(JobState.QUEUED.canTransitionTo(JobState.CANCELLING));
        assertTrue(JobState.QUEUED.canTransitionTo(JobState.CANCELLED));
        assertTrue(JobState.QUEUED.canTransitionTo(JobState.FAILED));
        assertTrue(JobState.QUEUED.canTransitionTo(JobState.QUEUED)); // self-transition allowed

        assertFalse(JobState.QUEUED.canTransitionTo(JobState.COMPLETED));
    }

    @Test
    public void testValidTransitionsFromRunning() {
        assertTrue(JobState.RUNNING.canTransitionTo(JobState.CANCELLING));
        assertTrue(JobState.RUNNING.canTransitionTo(JobState.CANCELLED));
        assertTrue(JobState.RUNNING.canTransitionTo(JobState.COMPLETED));
        assertTrue(JobState.RUNNING.canTransitionTo(JobState.FAILED));

        assertFalse(JobState.RUNNING.canTransitionTo(JobState.QUEUED));
    }

    @Test
    public void testValidTransitionsFromCancelling() {
        assertTrue(JobState.CANCELLING.canTransitionTo(JobState.CANCELLED));
        assertTrue(JobState.CANCELLING.canTransitionTo(JobState.FAILED));

        assertFalse(JobState.CANCELLING.canTransitionTo(JobState.RUNNING));
        assertFalse(JobState.CANCELLING.canTransitionTo(JobState.COMPLETED));
        assertFalse(JobState.CANCELLING.canTransitionTo(JobState.QUEUED));
    }

    @Test
    public void testTerminalStatesCannotTransition() {
        for (JobState target : JobState.values()) {
            if (target != JobState.CANCELLED) {
                assertFalse(JobState.CANCELLED.canTransitionTo(target));
            }
            if (target != JobState.COMPLETED) {
                assertFalse(JobState.COMPLETED.canTransitionTo(target));
            }
            if (target != JobState.FAILED) {
                assertFalse(JobState.FAILED.canTransitionTo(target));
            }
        }
    }

    @Test
    public void testNullTransitionRejected() {
        assertFalse(JobState.QUEUED.canTransitionTo(null));
        assertFalse(JobState.RUNNING.canTransitionTo(null));
    }
}
