# 🚀 Flutter Integration Guide - SecureGuard

Complete step-by-step guide to integrate SecureGuard Android Security SDK into your Flutter app.

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Android Configuration](#android-configuration)
4. [Flutter Implementation](#flutter-implementation)
5. [Testing](#testing)
6. [Troubleshooting](#troubleshooting)

---

## Prerequisites

- ✅ Flutter SDK installed (3.0+)
- ✅ Android Studio with NDK
- ✅ Kotlin 1.7+
- ✅ Gradle 7.5+
- ✅ Physical Android device (for testing)
- ✅ GitHub account (for JitPack)

---

## Installation

### Step 1: Add JitPack Repository

**android/settings.gradle:**
```gradle
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        google()
        mavenCentral()
        maven { url 'https://jitpack.io' }  // Add this line
    }
}
```

### Step 2: Add SecureGuard Dependency

**android/app/build.gradle:**
```gradle
android {
    compileSdk 33
    ndkVersion "29.0.13599879"  // Required for native code
    
    defaultConfig {
        minSdk 24  // SecureGuard requires API 24+
        targetSdk 33
    }
}

dependencies {
    // SecureGuard SDK (replace YOUR_USERNAME with your GitHub username)
    implementation 'com.github.YOUR_USERNAME:SecureGuard:1.0.0'
    
    // Required dependencies
    implementation 'androidx.core:core-ktx:1.12.0'
    implementation 'androidx.lifecycle:lifecycle-runtime-ktx:2.6.2'
    implementation 'org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3'
    implementation 'com.google.code.gson:gson:2.10.1'
}
```

**Alternative: Local AAR (Development)**
```gradle
dependencies {
    implementation files('libs/secureguard-release.aar')
    // ... other dependencies same as above
}
```

### Step 3: Sync Gradle
```bash
cd android
./gradlew clean
./gradlew build
```

---

## Android Configuration

### Step 1: Create MainApplication.kt

Create file: **android/app/src/main/kotlin/your/package/name/MainApplication.kt**

```kotlin
package your.package.name

import android.app.Application
import com.secureguard.sdk.SecureGuard
import com.secureguard.sdk.SecurityCallback
import com.secureguard.sdk.SecurityConfig
import com.secureguard.sdk.ThreatType
import com.secureguard.sdk.util.BackgroundSecurityHelper
import io.flutter.plugin.common.EventChannel

class MainApplication : Application(), SecurityCallback {
    
    companion object {
        private var eventSink: EventChannel.EventSink? = null
        
        fun setEventSink(sink: EventChannel.EventSink?) {
            eventSink = sink
        }
    }
    
    override fun onCreate() {
        super.onCreate()
        
        // Initialize SecureGuard
        SecureGuard.initialize(
            application = this,
            config = SecurityConfig.maximumSecurity(),
            callback = this
        )
        
        // Enable background screen security (black overlay)
        BackgroundSecurityHelper.register(this)
        
        println("✅ SecureGuard initialized")
    }
    
    override fun onThreatDetected(threatType: ThreatType, description: String) {
        println("🚨 THREAT: $threatType - $description")
        
        // Send threat to Flutter
        eventSink?.success(mapOf(
            "type" to "threat",
            "threatType" to threatType.name,
            "description" to description,
            "timestamp" to System.currentTimeMillis()
        ))
        
        // Force exit on critical threats
        if (threatType in listOf(
            ThreatType.ROOT_DETECTED,
            ThreatType.EMULATOR_DETECTED,
            ThreatType.DEBUGGER_DETECTED
        )) {
            android.os.Handler(mainLooper).postDelayed({
                android.os.Process.killProcess(android.os.Process.myPid())
            }, 3000)
        }
    }
    
    override fun onSecurityCheckComplete(passed: Boolean, threats: List<ThreatType>) {
        // Send status to Flutter
        eventSink?.success(mapOf(
            "type" to "status",
            "passed" to passed,
            "threats" to threats.map { it.name },
            "timestamp" to System.currentTimeMillis()
        ))
    }
}
```

### Step 2: Update MainActivity.kt

**android/app/src/main/kotlin/your/package/name/MainActivity.kt**

```kotlin
package your.package.name

import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel

class MainActivity: FlutterActivity() {
    
    private val SECURITY_CHANNEL = "com.secureguard/security"
    private val SECURITY_EVENTS = "com.secureguard/security_events"
    
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        
        // Method Channel for Flutter → Native calls
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, SECURITY_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "getSecurityStatus" -> {
                        result.success(mapOf(
                            "initialized" to true,
                            "mode" to "MAXIMUM_SECURITY",
                            "timestamp" to System.currentTimeMillis()
                        ))
                    }
                    else -> result.notImplemented()
                }
            }
        
        // Event Channel for Native → Flutter events
        EventChannel(flutterEngine.dartExecutor.binaryMessenger, SECURITY_EVENTS)
            .setStreamHandler(object : EventChannel.StreamHandler {
                override fun onListen(arguments: Any?, eventSink: EventChannel.EventSink?) {
                    MainApplication.setEventSink(eventSink)
                }
                
                override fun onCancel(arguments: Any?) {
                    MainApplication.setEventSink(null)
                }
            })
    }
}
```

### Step 3: Update AndroidManifest.xml

**android/app/src/main/AndroidManifest.xml**

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application
        android:name=".MainApplication"  <!-- Add this line -->
        android:label="Your App Name"
        android:icon="@mipmap/ic_launcher">
        
        <!-- Rest of your manifest -->
    </application>
</manifest>
```

---

## Flutter Implementation

### Step 1: Create Security Service

Create file: **lib/services/security_service.dart**

```dart
import 'package:flutter/services.dart';
import 'dart:async';

class SecurityService {
  static const platform = MethodChannel('com.secureguard/security');
  static const eventChannel = EventChannel('com.secureguard/security_events');
  
  Stream<Map<String, dynamic>> get securityEvents {
    return eventChannel.receiveBroadcastStream().map((event) {
      return Map<String, dynamic>.from(event);
    });
  }
  
  Future<Map<String, dynamic>> getSecurityStatus() async {
    try {
      final result = await platform.invokeMethod('getSecurityStatus');
      return Map<String, dynamic>.from(result);
    } on PlatformException catch (e) {
      print("Failed to get security status: ${e.message}");
      return {};
    }
  }
}
```

### Step 2: Create Security UI Widget

Create file: **lib/widgets/security_status_widget.dart**

```dart
import 'package:flutter/material.dart';
import '../services/security_service.dart';

class SecurityStatusWidget extends StatefulWidget {
  const SecurityStatusWidget({super.key});

  @override
  State<SecurityStatusWidget> createState() => _SecurityStatusWidgetState();
}

class _SecurityStatusWidgetState extends State<SecurityStatusWidget> {
  final _securityService = SecurityService();
  bool _isSecure = true;
  List<Map<String, dynamic>> _threats = [];
  
  @override
  void initState() {
    super.initState();
    _listenToSecurityEvents();
  }
  
  void _listenToSecurityEvents() {
    _securityService.securityEvents.listen((event) {
      if (event['type'] == 'threat') {
        setState(() {
          _isSecure = false;
          _threats.add(event);
        });
      } else if (event['type'] == 'status') {
        setState(() {
          _isSecure = event['passed'] == true;
        });
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          children: [
            Icon(
              _isSecure ? Icons.shield : Icons.warning,
              size: 64,
              color: _isSecure ? Colors.green : Colors.red,
            ),
            const SizedBox(height: 8),
            Text(
              _isSecure ? 'Device Secure' : 'Threats Detected!',
              style: TextStyle(
                fontSize: 20,
                fontWeight: FontWeight.bold,
                color: _isSecure ? Colors.green : Colors.red,
              ),
            ),
            if (_threats.isNotEmpty) ...[
              const SizedBox(height: 16),
              ..._threats.map((threat) => ListTile(
                leading: Icon(Icons.error, color: Colors.red),
                title: Text(threat['threatType'] ?? ''),
                subtitle: Text(threat['description'] ?? ''),
              )),
            ],
          ],
        ),
      ),
    );
  }
}
```

### Step 3: Use in Your App

**lib/main.dart**

```dart
import 'package:flutter/material.dart';
import 'widgets/security_status_widget.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Your App',
      home: Scaffold(
        appBar: AppBar(title: const Text('Your App')),
        body: Column(
          children: [
            const SecurityStatusWidget(),
            // Your app content
          ],
        ),
      ),
    );
  }
}
```

---

## Testing

### Test on Secure Device (Expected Result: ✅ Pass)
```bash
flutter run --release
```
**Expected:** App runs normally, shows "Device Secure"

### Test on Rooted Device (Expected Result: ❌ Detect & Exit)
1. Run on rooted device with Magisk/SuperSU
2. **Expected:** App detects root, shows "ROOT_DETECTED", closes after 3 seconds

### Test on Emulator (Expected Result: ❌ Detect & Exit)
```bash
flutter run
```
**Expected:** App detects emulator, shows "EMULATOR_DETECTED"

### Test Debugger Detection (Expected Result: ❌ Detect & Exit)
1. Run with debugger attached
2. **Expected:** App detects debugger, shows "DEBUGGER_DETECTED"

---

## Troubleshooting

### ❌ "Unresolved reference: SecureGuard"

**Solution:**
1. Check JitPack repository added to `settings.gradle`
2. Verify dependency added to `app/build.gradle`
3. Replace `YOUR_USERNAME` with actual GitHub username
4. Sync Gradle: `cd android && ./gradlew clean build`

### ❌ "Failed to load native library"

**Solution:**
1. Check NDK version: `ndkVersion "29.0.13599879"` in `build.gradle`
2. Clean and rebuild: `flutter clean && flutter pub get`
3. Check device ABI compatibility (arm64-v8a, armeabi-v7a)

### ❌ "PlatformException: Method not found"

**Solution:**
1. Verify channel names match in Kotlin and Dart
2. Check `MainApplication` is registered in `AndroidManifest.xml`
3. Restart app (hot reload won't work for native changes)

### ❌ Not detecting root on rooted device

**Solution:**
1. Test with actual Magisk/SuperSU installed
2. Check device is properly rooted (use Root Checker app)
3. Use `SecurityConfig.maximumSecurity()` mode
4. Check logs: `flutter logs | grep SecureGuard`

### ❌ JitPack build failed

**Solution:**
1. Check build logs: `https://jitpack.io/com/github/YOUR_USERNAME/SecureGuard/1.0.0/build.log`
2. Ensure release tag created: `git tag 1.0.0 && git push origin 1.0.0`
3. Verify `jitpack.yml` file exists in repository

---

## Security Modes

```kotlin
// Maximum security (Banking/Finance apps)
// Blocks: Emulators, Root, Debuggers, Frida, Xposed
SecurityConfig.maximumSecurity()

// Production mode (General apps)
// Blocks: Root, Debuggers, Frida, Xposed
// Allows: Emulators (for testing)
SecurityConfig.productionMode()

// Development mode (Testing only)
// Warnings only, no force exit
SecurityConfig.developmentMode()
```

Change in `MainApplication.kt`:
```kotlin
SecureGuard.initialize(
    application = this,
    config = SecurityConfig.productionMode(),  // Change here
    callback = this
)
```

---

## Advanced Features

### Custom Threat Handling

```kotlin
override fun onThreatDetected(threatType: ThreatType, description: String) {
    when (threatType) {
        ThreatType.ROOT_DETECTED -> {
            // Send to backend
            sendThreatToServer(threatType, description)
            // Then exit
            finishAffinity()
        }
        ThreatType.FRIDA_DETECTED -> {
            // Show warning only
            showWarningDialog()
        }
        else -> {
            // Default: force exit
            finishAffinity()
        }
    }
}
```

### Disable Background Screen Security

```kotlin
// In MainApplication.onCreate(), comment out:
// BackgroundSecurityHelper.register(this)
```

### Manual Security Check

```dart
// Trigger manual security check
await platform.invokeMethod('forceSecurityCheck');
```

---

## Complete Example

See **flutter_example/** folder for complete working example with:
- ✅ Full UI showing security status
- ✅ Real-time threat notifications
- ✅ Countdown timer before app exit
- ✅ Beautiful Material Design UI
- ✅ Ready to run and test

---

## Production Checklist

- [ ] Replace `YOUR_USERNAME` with actual GitHub username
- [ ] Test on rooted device (verifies root detection)
- [ ] Test on emulator (verifies emulator detection)
- [ ] Test with debugger (verifies debugger detection)
- [ ] Test on real device (verifies normal operation)
- [ ] Enable ProGuard for release builds
- [ ] Add error logging to backend
- [ ] Test user experience when threats detected
- [ ] Document security features for users
- [ ] Submit to app stores

---

## Support

- 📄 [SecureGuard Documentation](../README.md)
- 📄 [Publishing Guide](../GITHUB_PUBLISH_STEPS.md)
- 📄 [Flutter Example](flutter_example/README.md)
- 🐛 [Report Issues](https://github.com/YOUR_USERNAME/SecureGuard/issues)

---

**Your Flutter app now has enterprise-grade Android security!** 🛡️✨
