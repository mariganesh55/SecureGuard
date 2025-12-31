# SecureGuard - Android Security Library

A comprehensive security library for Android applications that provides runtime protection against common threats including root detection, emulator detection, debugger detection, and hooking framework detection.

## Features

- ✅ **Root Detection** - Multi-layered root detection using Java and native code
- ✅ **Emulator Detection** - Identifies if app is running on emulators/simulators
- ✅ **Debugger Detection** - Detects attached debuggers and debugging tools
- ✅ **Hooking Detection** - Identifies Frida, Xposed, LSPosed, and other hooking frameworks
- ✅ **Native Security** - Critical checks implemented in C++ for enhanced security
- ✅ **String Obfuscation** - All sensitive strings encrypted at runtime (like AppProtect)
- ✅ **Obfuscation Support** - ProGuard/R8 rules included for code protection
- ✅ **Easy Integration** - Simple API with callback support
- ✅ **Lightweight** - Minimal performance impact

## Installation

### Step 1: Add AAR to your project

1. Copy the `secureguard-release.aar` file to your app's `libs` folder
2. Add to your app's `build.gradle`:

```gradle
dependencies {
    implementation files('libs/secureguard-release.aar')
}
```

### Step 2: Initialize in your Application class

```kotlin
import android.app.Application
import com.secureguard.sdk.SecureGuard
import com.secureguard.sdk.SecurityConfig
import com.secureguard.sdk.SecurityCallback
import com.secureguard.sdk.ThreatType

class MyApplication : Application() {
    
    override fun onCreate() {
        super.onCreate()
        
        // Initialize SecureGuard
        SecureGuard.initialize(
            application = this,
            config = SecurityConfig.productionMode(),
            callback = object : SecurityCallback {
                override fun onThreatDetected(threatType: ThreatType, description: String) {
                    // Handle threat detection
                    when (threatType) {
                        ThreatType.ROOT_DETECTED -> {
                            // Show alert or block app
                        }
                        ThreatType.DEBUGGER_DETECTED -> {
                            // Log security event
                        }
                        else -> {}
                    }
                }
                
                override fun onSecurityCheckComplete(passed: Boolean, threats: List<ThreatType>) {
                    if (!passed) {
                        // App is compromised
                        finish()
                    }
                }
            }
        )
    }
}
```

## Configuration

### Pre-defined Configurations

```kotlin
// Maximum security (production)
SecurityConfig.maximumSecurity()

// Production mode (recommended)
SecurityConfig.productionMode()

// Development mode (testing)
SecurityConfig.developmentMode()
```

### Custom Configuration

```kotlin
val config = SecurityConfig(
    enableRootDetection = true,
    enableEmulatorDetection = true,
    enableDebuggerDetection = true,
    enableHookingDetection = true,
    blockOnThreat = true,
    showAlertOnThreat = true,
    alertMessage = "Security threat detected!",
    monitoringInterval = 60000L // Check every minute
)
```

## API Reference

### Main Methods

```kotlin
// Get SecureGuard instance
val secureGuard = SecureGuard.getInstance()

// Manual security scan
secureGuard?.scan()

// Individual checks
val isRooted = secureGuard?.isRooted()
val isEmulator = secureGuard?.isEmulator()
val isDebugging = secureGuard?.isDebugging()
val hookingFramework = secureGuard?.detectHooking()

// Cleanup
secureGuard?.destroy()
```

### Threat Types

- `ROOT_DETECTED` - Device is rooted
- `EMULATOR_DETECTED` - Running on emulator
- `DEBUGGER_DETECTED` - Debugger attached
- `HOOKING_DETECTED` - Hooking framework detected
- `TAMPERING_DETECTED` - App tampering detected
- `SCREEN_RECORDING_DETECTED` - Screen recording active

## Building from Source

### Prerequisites

- Android Studio Arctic Fox or later
- Android SDK API 24+
- NDK (for native code compilation)
- Gradle 8.0+

### Build Steps

```bash
# Clone the repository
git clone <repository-url>
cd SecureGuard

# Build the AAR
./gradlew :secureguard:assembleRelease

# Output will be at:
# secureguard/build/outputs/aar/secureguard-release.aar
```

## ProGuard/R8

ProGuard rules are automatically applied when using this library. No additional configuration needed.

## Security Considerations

1. **Defense in Depth**: This library is one layer of security. Combine it with:
   - SSL pinning
   - Code obfuscation
   - Server-side validation
   - Secure storage

2. **No Silver Bullet**: Determined attackers can bypass any client-side security. Use this library to raise the bar and detect common attack vectors.

3. **Regular Updates**: Keep the library updated to detect new attack techniques.

## Example Usage

### Banking App

```kotlin
SecureGuard.initialize(
    application = this,
    config = SecurityConfig.maximumSecurity(),
    callback = object : SecurityCallback {
        override fun onThreatDetected(threatType: ThreatType, description: String) {
            // Log to analytics
            Analytics.logSecurityEvent(threatType.name, description)
            
            // Show alert
            showSecurityAlert(description)
            
            // Block app
            finishAffinity()
        }
        
        override fun onSecurityCheckComplete(passed: Boolean, threats: List<ThreatType>) {
            if (passed) {
                // Proceed with app initialization
                initializeApp()
            }
        }
    }
)
```

## Architecture

SecureGuard uses a multi-layered security approach:

1. **Kotlin Layer** - High-level security checks and API
2. **Native Layer (C++)** - Low-level checks that are harder to bypass
3. **String Obfuscation** - All sensitive strings encrypted at runtime
4. **Callback System** - Real-time threat notifications
5. **Continuous Monitoring** - Optional background scanning

### String Obfuscation

Similar to AppProtect's approach with 500+ encrypted string methods, SecureGuard uses `StringObfuscator` to hide:
- SU binary paths (`/system/bin/su`, etc.)
- Root management app package names (Magisk, SuperSU, etc.)
- Xposed/LSPosed package names
- Frida detection strings (library names, file paths)
- System file paths (`/proc/self/maps`, etc.)
- Critical class names

All strings are encrypted with AES-128 and stored as base64. They're only decrypted at runtime when needed, preventing easy discovery through static analysis tools like JADX.

### Gaming App

```kotlin
SecureGuard.initialize(
    application = this,
    config = SecurityConfig(
        enableRootDetection = true,
        enableDebuggerDetection = true,
        enableHookingDetection = true,
        blockOnThreat = true,
        monitoringInterval = 30000L
    ),
    callback = object : SecurityCallback {
        override fun onThreatDetected(threatType: ThreatType, description: String) {
            // Flag account for review
            flagAccountForCheating()
            
            // Disable competitive features
            disableMultiplayer()
        }
        
        override fun onSecurityCheckComplete(passed: Boolean, threats: List<ThreatType>) {
            // Continue with limited functionality if threats detected
        }
    }
)
```

## Troubleshooting

### Library not loading

Ensure all dependencies are included and native libraries are properly packaged.

### False positives

Development builds may trigger some checks. Use `SecurityConfig.developmentMode()` for testing.

### Performance impact

The library is optimized for minimal impact. Continuous monitoring can be adjusted via `monitoringInterval`.

## License

[Add your license here]

## Support

[Add support contact information]

## Changelog

### Version 1.0.0
- Initial release
- Root detection with 4 methods
- Emulator detection with 5 methods  
- Debugger detection with 3 methods
- Frida/Xposed/LSPosed detection
- Native security checks (C++)
- AES-128 string obfuscation for sensitive data
- ProGuard rules for code obfuscation

## Credits

Inspired by security best practices from leading mobile security frameworks.
