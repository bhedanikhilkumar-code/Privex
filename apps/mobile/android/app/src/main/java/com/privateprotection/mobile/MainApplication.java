package com.privateprotection.mobile;

import android.app.Application;
import android.util.Log;

import com.privateprotection.mobile.core.MobileSecurityCoordinator;

/**
 * Main application class for Privex on Android.
 * Enforces zero-knowledge, local-only processing in memory.
 */
public class MainApplication extends Application {
    private static final String TAG = "PrivateProtectionApp";

    private static MainApplication sInstance;
    private MobileSecurityCoordinator securityCoordinator;

    public static MainApplication getInstance() {
        return sInstance;
    }

    public MobileSecurityCoordinator getSecurityCoordinator() {
        return securityCoordinator;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        sInstance = this;
        Log.i(TAG, "Privex Android Application initialized with local zero-knowledge configuration.");

        // Initialize Native Mobile Security Coordinator (Phase T1)
        securityCoordinator = MobileSecurityCoordinator.getInstance(this);
    }

    @Override
    public void onTrimMemory(int level) {
        super.onTrimMemory(level);
        if (securityCoordinator != null) {
            securityCoordinator.onTrimMemory(level);
        }
        com.privateprotection.mobile.core.AdaptiveResourceManager.getInstance(this).onTrimMemory(level);
    }

    @Override
    public void onLowMemory() {
        super.onLowMemory();
        if (securityCoordinator != null) {
            securityCoordinator.onLowMemory();
        }
        com.privateprotection.mobile.core.AdaptiveResourceManager.getInstance(this).onLowMemory();
    }
}
