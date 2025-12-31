# 🛡️ SecureGuard Flutter Example

Complete working example of SecureGuard Android Security SDK integrated with Flutter.

## 📁 Project Structure

```
flutter_example/
├── README.md                           # This file
├── pubspec.yaml                        # Flutter dependencies
├── lib/
│   └── main.dart                       # Flutter UI
└── android/
    ├── app/
    │   ├── build.gradle                # SecureGuard integration
    │   └── src/main/kotlin/
    │       └── MainActivity.kt         # Platform channel + Security
    └── settings.gradle                 # JitPack repository
```

## 🚀 Quick Start

### Prerequisites
- Flutter SDK installed
- Android Studio with NDK
- Physical Android device (rooted for testing)

### Step 1: Create Flutter Project
```bash
flutter create secureguard_flutter_demo --org com.yourcompany
cd secureguard_flutter_demo
```

### Step 2: Configure Android

**android/settings.gradle:**
```gradle
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        google()
        mavenCentral()
        maven { url 'https://jitpack.io' }  // Add this
    }
}
```

**android/app/build.gradle:**
```gradle
dependencies {
    implementation 'com.github.mariganesh55:SecureGuard:1.0.0'
    
    // Required dependencies
    implementation 'androidx.core:core-ktx:1.12.0'
    implementation 'androidx.lifecycle:lifecycle-runtime-ktx:2.6.2'
    implementation 'org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3'
    implementation 'com.google.code.gson:gson:2.10.1'
}
```

### Step 3: Copy Files from This Example

1. **Copy `MainActivity.kt`** → Your project's `android/app/src/main/kotlin/.../MainActivity.kt`
2. **Copy `MainApplication.kt`** → Same folder
3. **Copy `main.dart`** → Your project's `lib/main.dart`
4. **Update `AndroidManifest.xml`**

### Step 4: Run
```bash
flutter run
```

## 📱 Features Demonstrated

✅ **Platform Channels** - Flutter ↔ Native communication
✅ **Security Initialization** - SecureGuard setup in MainApplication
✅ **Real-time Threat Detection** - Callbacks from native to Flutter
✅ **Security Status UI** - Shows detected threats
✅ **Background Security** - Black overlay when app minimized
✅ **Force Exit** - App termination on critical threats

## 🎯 What Each File Does

### `MainApplication.kt`
- Initializes SecureGuard on app startup
- Configures security callbacks
- Sends threats to Flutter via EventChannel

### `MainActivity.kt`
- Sets up MethodChannel for Flutter communication
- Exposes security methods to Flutter
- Handles platform-specific calls

### `main.dart`
- Flutter UI showing security status
- Receives threat notifications from native
- Displays real-time security information
- Shows detected threats with icons

## 🧪 Testing

### Test Root Detection
1. Run on rooted device
2. App should show "ROOT_DETECTED" threat
3. App force closes after 3 seconds

### Test Emulator Detection
1. Run on Android Studio emulator
2. App should show "EMULATOR_DETECTED" threat
3. App force closes

### Test Debugger Detection
1. Run in debug mode
2. App should show "DEBUGGER_DETECTED" threat

### Test on Real Device
1. Run on non-rooted physical device
2. App should show "✅ Device Secure"
3. All checks passed

## 📊 Expected Behavior

**On Secure Device:**
```
🛡️ SecureGuard Status
✅ Device Secure
No threats detected

Security Checks:
✓ Root Detection: Passed
✓ Emulator Detection: Passed  
✓ Debugger Detection: Passed
✓ Hooking Detection: Passed
```

**On Rooted Device:**
```
🛡️ SecureGuard Status
⚠️ Threats Detected!

Detected Threats:
🔴 ROOT_DETECTED
Device is rooted

App will close in 3 seconds...
```

## 🔧 Customization

### Change Security Mode
In `MainApplication.kt`:
```kotlin
// Maximum security (banking apps)
config = SecurityConfig.maximumSecurity()

// Production mode (general apps)
config = SecurityConfig.productionMode()

// Development mode (testing)
config = SecurityConfig.developmentMode()
```

### Handle Threats Differently
```kotlin
override fun onThreatDetected(threatType: ThreatType, description: String) {
    // Option 1: Force exit (default)
    finishAffinity()
    
    // Option 2: Show warning only
    sendToFlutter(threatType, description)
    
    // Option 3: Send to backend
    logThreatToServer(threatType, description)
}
```

## 📚 Learn More

- [SecureGuard Documentation](../README.md)
- [Integration Guide](../INTEGRATION_GUIDE.md)
- [Publishing Guide](../GITHUB_PUBLISH_STEPS.md)
- [Flutter Platform Channels](https://docs.flutter.dev/platform-integration/platform-channels)

## 🆘 Troubleshooting

### "Unresolved reference: SecureGuard"
- Add JitPack repository to `settings.gradle`
- Add all required dependencies to `app/build.gradle`
- Sync Gradle files

### App Not Detecting Root
- Check device is actually rooted
- Test with SuperSU/Magisk installed
- Enable "Debug Mode" in SecurityConfig for testing

### Flutter Not Receiving Events
- Check MethodChannel name matches: "com.secureguard.example/security"
- Verify EventChannel setup in MainActivity
- Check logs for errors

## 💡 Pro Tips

1. **Always test on real rooted device** - Emulators may give false positives
2. **Use ProductionMode during development** - MaximumSecurity blocks emulators
3. **Add error handling** - Platform channels can throw PlatformException
4. **Log threats to backend** - Monitor security events in production
5. **Add user feedback** - Show why app is closing (root detected, etc.)

---

**This example demonstrates enterprise-grade mobile security in Flutter!** 🚀✨
