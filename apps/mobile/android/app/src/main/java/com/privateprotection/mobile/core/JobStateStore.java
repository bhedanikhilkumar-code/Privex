package com.privateprotection.mobile.core;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Lightweight, thread-safe persistence and crash recovery store for security jobs (Phase T1).
 *
 * Implements truthful process-death recovery:
 * If an app process terminates abruptly, jobs left in QUEUED or RUNNING state
 * are recovered to FAILED with "PROCESS_TERMINATED_ABRUPTLY". Never falsely claims completion.
 */
public class JobStateStore {
    private static final String TAG = "JobStateStore";
    private static final String PREF_NAME = "pp_security_jobs_v1";
    private static final String KEY_JOB_IDS = "job_ids_index";
    private static final int MAX_HISTORY_ENTRIES = 50;

    private final SharedPreferences prefs;
    private final Map<String, SecurityJob> memoryIndex = Collections.synchronizedMap(new LinkedHashMap<>());

    public JobStateStore(Context context) {
        this(context.getApplicationContext().getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE));
    }

    public JobStateStore(SharedPreferences prefs) {
        this.prefs = prefs;
        loadAllPersisted();
    }

    private synchronized void loadAllPersisted() {
        String indexRaw = prefs.getString(KEY_JOB_IDS, "[]");
        try {
            JSONArray arr = new JSONArray(indexRaw);
            for (int i = 0; i < arr.length(); i++) {
                try {
                    String id = arr.getString(i);
                    String jobRaw = prefs.getString("job_" + id, null);
                    if (jobRaw != null) {
                        JSONObject obj = new JSONObject(jobRaw);
                        SecurityJob job = SecurityJob.fromJSON(obj);
                        if (job != null) {
                            memoryIndex.put(job.getId(), job);
                        }
                    }
                } catch (Exception e) {
                    Log.w(TAG, "Skipping corrupted individual job record in index", e);
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to load persisted security job index", e);
        }
    }

    /**
     * Executes process recovery protocol.
     * Transitions any orphaned QUEUED or RUNNING job to FAILED with
     * reason 'PROCESS_TERMINATED_ABRUPTLY'.
     *
     * @return List of recovered orphaned jobs
     */
    public synchronized List<SecurityJob> recoverOrphanedJobs() {
        List<SecurityJob> recovered = new ArrayList<>();
        long now = System.currentTimeMillis();

        for (SecurityJob job : memoryIndex.values()) {
            JobState state = job.getState();
            if (state == JobState.QUEUED || state == JobState.RUNNING || state == JobState.CANCELLING) {
                job.transitionTo(JobState.FAILED, "PROCESS_TERMINATED_ABRUPTLY");
                job.setCompletedAtMs(now);
                persistJob(job);
                recovered.add(job);
                Log.w(TAG, "Recovered orphaned job " + job.getId() + " (was " + state + ") -> FAILED");
            }
        }
        return recovered;
    }

    public synchronized void persistJob(SecurityJob job) {
        if (job == null) return;
        memoryIndex.put(job.getId(), job);

        try {
            SharedPreferences.Editor editor = prefs.edit();
            editor.putString("job_" + job.getId(), job.toJSON().toString());

            // Update index list, bounding to MAX_HISTORY_ENTRIES
            List<String> ids = new ArrayList<>(memoryIndex.keySet());
            while (ids.size() > MAX_HISTORY_ENTRIES) {
                String oldest = ids.remove(0);
                memoryIndex.remove(oldest);
                editor.remove("job_" + oldest);
            }

            JSONArray arr = new JSONArray(ids);
            editor.putString(KEY_JOB_IDS, arr.toString());
            editor.apply();
        } catch (Exception e) {
            Log.e(TAG, "Failed to persist job " + job.getId(), e);
        }
    }

    public synchronized SecurityJob getJob(String jobId) {
        if (jobId == null) return null;
        return memoryIndex.get(jobId);
    }

    public synchronized List<SecurityJob> getAllJobs() {
        return new ArrayList<>(memoryIndex.values());
    }

    public synchronized void clearHistory() {
        memoryIndex.clear();
        prefs.edit().clear().apply();
    }
}
