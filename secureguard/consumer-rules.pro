# Consumer ProGuard rules - Applied to apps using this library

# Keep ALL classes in SDK package
-keep class com.secureguard.sdk.** { *; }
-keepclassmembers class com.secureguard.sdk.** { *; }

# Preserve all annotations
-keepattributes *Annotation*

# Keep Kotlin metadata
-keep class kotlin.Metadata { *; }

# Keep companion objects
-keepclassmembers class * {
    ** Companion;
}
