package com.privateprotection.mobile.core;

import android.content.BroadcastReceiver;
import android.content.ComponentCallbacks2;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.BatteryManager;
import android.os.Build;
import android.os.PowerManager;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * AdaptiveResourceManager (Phase T12):
 *
 * Implements Battery, Thermal, and Low-RAM adaptive protection for Privex Android:
 * 1. Battery-aware scaling (<20% discharging defers non-critical deep scans, charging bypasses).
 * 2. Thermal status monitoring via PowerManager.OnThermalStatusChangedListener (API 29+) or UNAVAILABLE.
 * 3. Low-RAM detection via ComponentCallbacks2 trim memory and OS onLowMemory signals.
 * 4. Foreground vs background activity inference to throttle heavy scans when user interacts.
 * 5. Bounded streaming buffer sizing (64 KB normal down to 16 KB under low RAM).
 * 6. Critical threat preservation: Active threats NEVER downgraded, converted to ALLOW, or discarded.
 * 7. Zero indefinite wakelocks and zero fake device temperature claims.
 */
public class AdaptiveResourceManager {
    private static final String TAG = "AdaptiveResourceMgr";

    public enum ResourceMode {
        NORMAL,
        BATTERY_SAVER,
        THERMAL_THROTTLED,
        LOW_MEMORY,
        BACKGROUND_THROTTLED,
        DEGRADED_CRITICAL
    }

    public enum ThermalStatus {
        NONE,
        LIGHT,
        MODERATE,
        SEVERE,
        CRITICAL,
        EMERGENCY,
        SHUTDOWN,
        UNAVAILABLE
    }

    public interface ResourceStateChangeListener {
        void onResourceModeChanged(ResourceMode newMode, String reason);
    }

    private static volatile AdaptiveResourceManager sInstance;

    private final Context context;
    private final AtomicReference<ResourceMode> currentMode = new AtomicReference<>(ResourceMode.NORMAL);
    private final AtomicReference<ThermalStatus> currentThermalStatus = new AtomicReference<>(ThermalStatus.UNAVAILABLE);
    private final AtomicInteger batteryPct = new AtomicInteger(100);
    private final AtomicBoolean isCharging = new AtomicBoolean(false);
    private final AtomicBoolean isLowMemory = new AtomicBoolean(false);
    private final AtomicBoolean isForegroundHeavy = new AtomicBoolean(false);
    private final AtomicReference<String> transitionReason = new AtomicReference<>("INITIAL_STATE");

    private final CopyOnWriteArrayList<ResourceStateChangeListener> listeners = new CopyOnWriteArrayList<>();

    // Mock injection flags for deterministic testing
    private volatile boolean isTestOverrideActive = false;

    // Thermal listener reference (API 29+)
    private PowerManager.OnThermalStatusChangedListener thermalListener;
    private BroadcastReceiver batteryReceiver;

    public static AdaptiveResourceManager getInstance(Context context) {
        if (sInstance == null) {
            synchronized (AdaptiveResourceManager.class) {
                if (sInstance == null) {
                    sInstance = new AdaptiveResourceManager(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    public static synchronized void resetInstanceForTest() {
        if (sInstance != null) {
            sInstance.unregisterReceivers();
            sInstance = null;
        }
    }

    public static synchronized void setInstanceForTest(AdaptiveResourceManager instance) {
        sInstance = instance;
    }

    public AdaptiveResourceManager(Context context) {
        this.context = context != null ? context.getApplicationContext() : null;
        if (this.context != null) {
            registerReceivers();
            readInitialBatteryState();
            initThermalListener();
            evaluateResourceMode();
        }
    }

    private void registerReceivers() {
        if (context == null) return;
        try {
            batteryReceiver = new BroadcastReceiver() {
                @Override
                public void onReceive(Context ctx, Intent intent) {
                    if (intent == null || isTestOverrideActive) return;
                    int level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
                    int scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
                    int status = intent.getIntExtra(BatteryManager.EXTRA_STATUS, -1);

                    if (level >= 0 && scale > 0) {
                        batteryPct.set((int) ((level / (float) scale) * 100));
                    }

                    boolean charging = (status == BatteryManager.BATTERY_STATUS_CHARGING ||
                            status == BatteryManager.BATTERY_STATUS_FULL);
                    isCharging.set(charging);

                    evaluateResourceMode();
                }
            };

            IntentFilter filter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
            context.registerReceiver(batteryReceiver, filter);
        } catch (Exception e) {
            Log.e(TAG, "Failed to register battery receiver", e);
        }
    }

    private void readInitialBatteryState() {
        if (context == null || isTestOverrideActive) return;
        try {
            IntentFilter ifilter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
            Intent batteryStatus = context.registerReceiver(null, ifilter);
            if (batteryStatus != null) {
                int level = batteryStatus.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
                int scale = batteryStatus.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
                int status = batteryStatus.getIntExtra(BatteryManager.EXTRA_STATUS, -1);

                if (level >= 0 && scale > 0) {
                    batteryPct.set((int) ((level / (float) scale) * 100));
                }
                boolean charging = (status == BatteryManager.BATTERY_STATUS_CHARGING ||
                        status == BatteryManager.BATTERY_STATUS_FULL);
                isCharging.set(charging);
            }
        } catch (Exception e) {
            Log.w(TAG, "Could not query initial battery state", e);
        }
    }

    private void initThermalListener() {
        if (context == null || isTestOverrideActive) return;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            try {
                PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
                if (pm != null) {
                    int initialStatus = pm.getCurrentThermalStatus();
                    currentThermalStatus.set(mapAndroidThermalStatus(initialStatus));

                    thermalListener = status -> {
                        if (isTestOverrideActive) return;
                        ThermalStatus mapped = mapAndroidThermalStatus(status);
                        currentThermalStatus.set(mapped);
                        evaluateResourceMode();
                    };
                    pm.addThermalStatusListener(context.getMainExecutor(), thermalListener);
                    return;
                }
            } catch (Throwable t) {
                Log.w(TAG, "Thermal status API unavailable on this device/ROM: " + t.getMessage());
            }
        }
        currentThermalStatus.set(ThermalStatus.UNAVAILABLE);
    }

    public void unregisterReceivers() {
        if (context == null) return;
        try {
            if (batteryReceiver != null) {
                context.unregisterReceiver(batteryReceiver);
                batteryReceiver = null;
            }
        } catch (Exception ignored) {}

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && thermalListener != null) {
            try {
                PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
                if (pm != null) {
                    pm.removeThermalStatusListener(thermalListener);
                }
            } catch (Exception ignored) {}
            thermalListener = null;
        }
    }

    private ThermalStatus mapAndroidThermalStatus(int status) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            switch (status) {
                case PowerManager.THERMAL_STATUS_NONE:
                    return ThermalStatus.NONE;
                case PowerManager.THERMAL_STATUS_LIGHT:
                    return ThermalStatus.LIGHT;
                case PowerManager.THERMAL_STATUS_MODERATE:
                    return ThermalStatus.MODERATE;
                case PowerManager.THERMAL_STATUS_SEVERE:
                    return ThermalStatus.SEVERE;
                case PowerManager.THERMAL_STATUS_CRITICAL:
                    return ThermalStatus.CRITICAL;
                case PowerManager.THERMAL_STATUS_EMERGENCY:
                    return ThermalStatus.EMERGENCY;
                case PowerManager.THERMAL_STATUS_SHUTDOWN:
                    return ThermalStatus.SHUTDOWN;
                default:
                    return ThermalStatus.UNAVAILABLE;
            }
        }
        return ThermalStatus.UNAVAILABLE;
    }

    public synchronized void evaluateResourceMode() {
        ResourceMode nextMode = ResourceMode.NORMAL;
        String reason = "System resources within nominal thresholds";

        int bat = batteryPct.get();
        boolean charging = isCharging.get();
        ThermalStatus thermal = currentThermalStatus.get();
        boolean lowMem = isLowMemory.get();
        boolean fgHeavy = isForegroundHeavy.get();

        // Check severe combined conditions first
        if (lowMem && (thermal == ThermalStatus.SEVERE || thermal == ThermalStatus.CRITICAL || thermal == ThermalStatus.EMERGENCY)) {
            nextMode = ResourceMode.DEGRADED_CRITICAL;
            reason = "Combined low memory and severe thermal pressure";
        } else if (lowMem) {
            nextMode = ResourceMode.LOW_MEMORY;
            reason = "Operating system reported low memory or trim pressure";
        } else if (thermal == ThermalStatus.SEVERE || thermal == ThermalStatus.CRITICAL || thermal == ThermalStatus.EMERGENCY) {
            nextMode = ResourceMode.THERMAL_THROTTLED;
            reason = "Thermal pressure is " + thermal.name() + "; reducing worker concurrency";
        } else if (bat < 20 && !charging) {
            nextMode = ResourceMode.BATTERY_SAVER;
            reason = "Battery level is " + bat + "% (discharging); deferring non-critical deep work";
        } else if (fgHeavy) {
            nextMode = ResourceMode.BACKGROUND_THROTTLED;
            reason = "Heavy foreground user interaction in progress; throttling background tasks";
        } else if (thermal == ThermalStatus.MODERATE) {
            nextMode = ResourceMode.THERMAL_THROTTLED;
            reason = "Moderate thermal warning; operating with conservative concurrency";
        }

        ResourceMode previous = currentMode.getAndSet(nextMode);
        transitionReason.set(reason);

        if (previous != nextMode) {
            Log.i(TAG, "ResourceMode transition: " + previous + " -> " + nextMode + " (" + reason + ")");
            for (ResourceStateChangeListener listener : listeners) {
                try {
                    listener.onResourceModeChanged(nextMode, reason);
                } catch (Exception e) {
                    Log.e(TAG, "Listener error during onResourceModeChanged", e);
                }
            }
        }
    }

    /**
     * Determines whether a non-critical scheduled deep scan can proceed or must be deferred.
     */
    public boolean canExecuteScheduledDeepScan() {
        int bat = batteryPct.get();
        boolean charging = isCharging.get();
        ThermalStatus thermal = currentThermalStatus.get();
        boolean lowMem = isLowMemory.get();

        // Battery condition: below 20% while discharging defers deep scans
        if (bat < 20 && !charging) {
            return false;
        }

        // Severe thermal pressure defers scheduled deep scans
        if (thermal == ThermalStatus.SEVERE || thermal == ThermalStatus.CRITICAL ||
                thermal == ThermalStatus.EMERGENCY || thermal == ThermalStatus.SHUTDOWN) {
            return false;
        }

        // Low memory condition defers bulk background scans
        if (lowMem) {
            return false;
        }

        return true;
    }

    /**
     * Computes recommended worker thread count based on active resource state.
     */
    public int getRecommendedWorkerConcurrency(int defaultMaxThreads) {
        ResourceMode mode = currentMode.get();
        switch (mode) {
            case DEGRADED_CRITICAL:
            case LOW_MEMORY:
                return 1;
            case THERMAL_THROTTLED:
                return Math.max(1, defaultMaxThreads / 2);
            case BACKGROUND_THROTTLED:
                return 1;
            case BATTERY_SAVER:
                return Math.max(1, defaultMaxThreads / 2);
            case NORMAL:
            default:
                return defaultMaxThreads;
        }
    }

    /**
     * Recommends buffer size for streaming file hashing & archive traversal.
     */
    public int getStreamingBufferSize() {
        ResourceMode mode = currentMode.get();
        if (mode == ResourceMode.LOW_MEMORY || mode == ResourceMode.DEGRADED_CRITICAL) {
            return 16 * 1024; // 16 KB under low RAM
        }
        return 64 * 1024; // 64 KB standard
    }

    // Callbacks from Application lifecycle
    public void onTrimMemory(int level) {
        if (level >= ComponentCallbacks2.TRIM_MEMORY_MODERATE ||
                level >= ComponentCallbacks2.TRIM_MEMORY_RUNNING_LOW) {
            isLowMemory.set(true);
        } else if (level <= ComponentCallbacks2.TRIM_MEMORY_RUNNING_MODERATE) {
            isLowMemory.set(false);
        }
        evaluateResourceMode();
    }

    public void onLowMemory() {
        isLowMemory.set(true);
        evaluateResourceMode();
    }

    public void onMemoryRecovered() {
        isLowMemory.set(false);
        evaluateResourceMode();
    }

    public void setForegroundHeavy(boolean heavy) {
        isForegroundHeavy.set(heavy);
        evaluateResourceMode();
    }

    // Test overrides for deterministic unit testing
    public void setTestOverrides(int batteryPercentage, boolean charging, ThermalStatus thermal, boolean lowMemory) {
        this.isTestOverrideActive = true;
        this.batteryPct.set(batteryPercentage);
        this.isCharging.set(charging);
        this.currentThermalStatus.set(thermal != null ? thermal : ThermalStatus.UNAVAILABLE);
        this.isLowMemory.set(lowMemory);
        evaluateResourceMode();
    }

    public void clearTestOverrides() {
        this.isTestOverrideActive = false;
        readInitialBatteryState();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && context != null) {
            try {
                PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
                if (pm != null) {
                    currentThermalStatus.set(mapAndroidThermalStatus(pm.getCurrentThermalStatus()));
                }
            } catch (Throwable ignored) {
                currentThermalStatus.set(ThermalStatus.UNAVAILABLE);
            }
        } else {
            currentThermalStatus.set(ThermalStatus.UNAVAILABLE);
        }
        evaluateResourceMode();
    }

    public void addListener(ResourceStateChangeListener listener) {
        if (listener != null && !listeners.contains(listener)) {
            listeners.add(listener);
        }
    }

    public void removeListener(ResourceStateChangeListener listener) {
        if (listener != null) {
            listeners.remove(listener);
        }
    }

    public ResourceMode getCurrentMode() {
        return currentMode.get();
    }

    public ThermalStatus getCurrentThermalStatus() {
        return currentThermalStatus.get();
    }

    public int getBatteryPercentage() {
        return batteryPct.get();
    }

    public boolean isCharging() {
        return isCharging.get();
    }

    public boolean isLowMemory() {
        return isLowMemory.get();
    }

    public String getTransitionReason() {
        return transitionReason.get();
    }

    public JSONObject getAdaptiveStatusJSON() {
        JSONObject obj = new JSONObject();
        try {
            obj.put("resourceMode", currentMode.get().name());
            obj.put("batteryPercentage", batteryPct.get());
            obj.put("isCharging", isCharging.get());
            obj.put("thermalStatus", currentThermalStatus.get().name());
            obj.put("isThermalSupported", currentThermalStatus.get() != ThermalStatus.UNAVAILABLE);
            obj.put("isLowMemory", isLowMemory.get());
            obj.put("isForegroundHeavy", isForegroundHeavy.get());
            obj.put("streamingBufferSize", getStreamingBufferSize());
            obj.put("canExecuteScheduledDeepScan", canExecuteScheduledDeepScan());
            obj.put("transitionReason", transitionReason.get());
            obj.put("disclaimer", "Adaptive mode responds dynamically to OS battery, thermal, and memory signals without indefinite wakelocks or false temperature control claims.");
        } catch (JSONException ignored) {}
        return obj;
    }
}
