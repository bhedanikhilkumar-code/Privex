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

# Tink and Security Crypto compile-time annotation suppressions
-dontwarn com.google.errorprone.annotations.**
-dontwarn javax.annotation.**
-dontwarn com.google.crypto.tink.**
-dontwarn androidx.security.crypto.**

