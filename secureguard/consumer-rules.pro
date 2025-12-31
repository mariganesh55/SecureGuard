# Consumer ProGuard rules - Applied to apps using this library

# Keep ALL public API classes and members
-keep public class com.secureguard.sdk.** {
    public *;
}

# Keep util classes
-keep public class com.secureguard.sdk.util.** {
    public *;
}

# Keep BackgroundSecurityHelper specifically
-keep public class com.secureguard.sdk.util.BackgroundSecurityHelper {
    public *;
}
