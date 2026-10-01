# Private Protection ProGuard Rules
# Preserve domain models and native interface contracts

-keep class com.privateprotection.mobile.** { *; }
-dontwarn com.privateprotection.mobile.**

# Strip debug log calls in release builds to prevent accidental telemetry leakage
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
}
