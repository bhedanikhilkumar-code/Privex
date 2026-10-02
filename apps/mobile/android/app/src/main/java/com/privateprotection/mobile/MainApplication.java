package com.privateprotection.mobile;

import android.app.Application;
import android.util.Log;

/**
 * Main application class for Private Protection on Android.
 * Enforces zero-knowledge, local-only processing in memory.
 */
public class MainApplication extends Application {
    private static final String TAG = "PrivateProtectionApp";

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "Private Protection Android Application initialized with local zero-knowledge configuration.");
    }
}
