# ProGuard rules for SecureGuard library

# Keep public API
-keep public class com.secureguard.sdk.SecureGuard {
    public *;
}

-keep public class com.secureguard.sdk.SecurityConfig {
    public *;
}

-keep public class com.secureguard.sdk.SecurityCallback {
    public *;
}

-keep public class com.secureguard.sdk.ThreatType {
    public *;
}

# Keep native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep classes with JNI
-keepclasseswithmembers class com.secureguard.sdk.core.NativeSecurityBridge {
    native <methods>;
}

# Keep StringObfuscator but obfuscate method names for extra security
# The decrypt method must be kept to work properly
-keep class com.secureguard.sdk.util.StringObfuscator {
    private static *** KEY;
    private static *** IV;
    private static *** decrypt(java.lang.String);
}

# Obfuscate all string method names (suPath1, rootApp1, etc.)
# This adds another layer of obfuscation on top of encryption
-keepclassmembers class com.secureguard.sdk.util.StringObfuscator {
    public static *** *();
}
-allowaccessmodification

# Obfuscate internal classes
-repackageclasses 'com.secureguard.internal'

# Remove logging in release
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
}

# Keep enums
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# Optimize
-optimizationpasses 5
-dontusemixedcaseclassnames
-dontskipnonpubliclibraryclasses
-verbose
-optimizations !code/simplification/arithmetic,!field/*,!class/merging/*

# Keep annotation attributes
-keepattributes *Annotation*
-keepattributes Signature
-keepattributes Exceptions
