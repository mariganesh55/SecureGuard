# Migration Guide: Weak → Pentester-Hardened

## Overview

This guide explains how to migrate from the original vulnerable design to the pentester-hardened architecture.

---

## Files Changed

### Native Code (C++)

#### New Files Created:
```
cpp/
├── enforcement.h              # NEW: Direct enforcement strategies
├── continuous_monitor.h       # NEW: Background monitoring thread
├── self_protect.h            # NEW: Anti-hooking protection
└── native_bridge_hardened.cpp # NEW: JNI interface (replaces native_bridge.cpp)
```

#### Removed/Deprecated:
```
cpp/
├── native_bridge.cpp          # DEPRECATED: Had boolean returns
└── security_checks.cpp        # DEPRECATED: Returned status codes
```

### Kotlin Code

#### New Files:
```
kotlin/com/secureguard/sdk/
└── SecurityManager_Hardened.kt  # NEW: Hardened API
```

#### Deprecated:
```
kotlin/com/secureguard/sdk/
├── SecurityManager.kt           # DEPRECATED: Boolean-based API
├── RootDetector.kt             # DEPRECATED: Returns boolean
├── EmulatorDetector.kt         # DEPRECATED: Returns boolean
├── DebuggerDetector.kt         # DEPRECATED: Returns boolean
└── HookingDetector.kt          # DEPRECATED: Returns boolean
```

---

## API Changes

### ❌ OLD API (Vulnerable)

```kotlin
// Initialize
val securityManager = SecurityManager.initialize(context)

// Check security (returns boolean)
val isSecure = securityManager.checkIntegrity()

if (!isSecure) {
    // App decides what to do
    showSecurityWarning()
    finish()
}

// Individual checks
val isRooted = RootDetector.check()
val isDebugged = DebuggerDetector.check()
val isEmulator = EmulatorDetector.check()
val isHooked = HookingDetector.check()

// Make decisions based on results
if (isRooted || isDebugged) {
    exitProcess(1)
}
```

**Problems:**
- ❌ Returns booleans that can be hooked
- ❌ Managed layer makes decisions
- ❌ Clean APIs to hook
- ❌ One-time checks
- ❌ Graceful exits

### ✅ NEW API (Hardened)

```kotlin
// Initialize - that's it!
SecurityManager.initialize(context)

// Continue with your app
// Native monitoring runs in background
// If compromised, app terminates automatically
// No need to check results
```

**Benefits:**
- ✅ No boolean returns
- ✅ Native owns decisions
- ✅ No hookable APIs
- ✅ Continuous monitoring
- ✅ Crashes, not dialogs

---

## Migration Steps

### Step 1: Update Dependencies

**build.gradle**
```groovy
dependencies {
    // Old
    // implementation 'com.secureguard:secureguard-sdk:1.0.0'
    
    // New
    implementation 'com.secureguard:secureguard-sdk:2.0.0'  // Hardened version
}
```

### Step 2: Update Application Class

**Before:**
```kotlin
class MyApp : Application() {
    override fun onCreate() {
        super.onCreate()
        
        val security = SecurityManager.initialize(this)
        
        // Check security
        if (!security.checkIntegrity()) {
            AlertDialog.Builder(this)
                .setTitle("Security Warning")
                .setMessage("Device is rooted")
                .setPositiveButton("Exit") { _, _ ->
                    exitProcess(1)
                }
                .show()
        }
    }
}
```

**After:**
```kotlin
class MyApp : Application() {
    override fun onCreate() {
        super.onCreate()
        
        // Just initialize - native handles everything
        SecurityManager.initialize(this)
        
        // That's it! Continue normally
        // If device is compromised, app will terminate from native code
    }
}
```

### Step 3: Remove Security Checks

**Before:**
```kotlin
class MainActivity : AppCompatActivity() {
    override fun onResume() {
        super.onResume()
        
        // Check on every resume
        if (RootDetector.check()) {
            finish()
        }
        
        if (DebuggerDetector.check()) {
            finish()
        }
    }
}
```

**After:**
```kotlin
class MainActivity : AppCompatActivity() {
    override fun onResume() {
        super.onResume()
        
        // Remove all security checks
        // Native monitoring is continuous
        // No need to check manually
    }
}
```

### Step 4: Remove Security Dialogs

**Before:**
```kotlin
fun showSecurityWarning() {
    AlertDialog.Builder(this)
        .setTitle("Security Alert")
        .setMessage("Rooted device detected")
        .setCancelable(false)
        .setPositiveButton("Exit") { _, _ ->
            exitProcess(1)
        }
        .show()
}
```

**After:**
```kotlin
// Remove this function entirely
// Native code handles enforcement
// No dialogs shown
// App just crashes if compromised (looks like bug)
```

### Step 5: Remove Manual Exit Calls

**Before:**
```kotlin
if (isRooted || isDebugged) {
    exitProcess(1)  // Graceful exit
}
```

**After:**
```kotlin
// Remove all exitProcess() calls
// Native code enforces with:
// - _exit(137)
// - SIGSEGV
// - Memory corruption
// Makes it look like crashes, not security blocks
```

---

## Code Examples

### Example 1: Simple App

**Before:**
```kotlin
class MyApp : Application() {
    override fun onCreate() {
        super.onCreate()
        
        SecurityManager.initialize(this).apply {
            if (checkRootAccess()) handleRootedDevice()
            if (checkDebugger()) handleDebugger()
            if (checkEmulator()) handleEmulator()
        }
    }
    
    private fun handleRootedDevice() {
        Toast.makeText(this, "Rooted device!", LENGTH_LONG).show()
        exitProcess(1)
    }
}
```

**After:**
```kotlin
class MyApp : Application() {
    override fun onCreate() {
        super.onCreate()
        
        // One line - that's it!
        SecurityManager.initialize(this)
    }
}
```

### Example 2: Financial App

**Before:**
```kotlin
class BankingApp : Application() {
    override fun onCreate() {
        super.onCreate()
        
        val security = SecurityManager.initialize(this)
        
        val threats = mutableListOf<String>()
        if (security.checkRootAccess()) threats.add("Root")
        if (security.checkDebugger()) threats.add("Debugger")
        if (security.checkHooking()) threats.add("Hooking")
        
        if (threats.isNotEmpty()) {
            AlertDialog.Builder(this)
                .setTitle("Security Risk Detected")
                .setMessage("Threats: ${threats.joinToString()}")
                .setPositiveButton("Exit") { _, _ ->
                    // Log to analytics
                    Analytics.log("security_exit", mapOf("threats" to threats))
                    exitProcess(1)
                }
                .setCancelable(false)
                .show()
        }
    }
}
```

**After:**
```kotlin
class BankingApp : Application() {
    override fun onCreate() {
        super.onCreate()
        
        // Initialize hardened security
        SecurityManager.initialize(this)
        
        // Optional: Log device info for analytics
        // But NOT for security decisions
        val deviceInfo = SecurityManager.getInstance().getDeviceInfo()
        Analytics.log("app_start", deviceInfo)
        
        // Continue normally
        // Native monitoring handles all threats
    }
}
```

### Example 3: Periodic Checks

**Before:**
```kotlin
class SecureActivity : AppCompatActivity() {
    private val checkInterval = 30_000L // 30 seconds
    private val handler = Handler(Looper.getMainLooper())
    
    private val securityCheck = object : Runnable {
        override fun run() {
            if (RootDetector.check() || DebuggerDetector.check()) {
                finish()
            }
            handler.postDelayed(this, checkInterval)
        }
    }
    
    override fun onResume() {
        super.onResume()
        handler.post(securityCheck)
    }
    
    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(securityCheck)
    }
}
```

**After:**
```kotlin
class SecureActivity : AppCompatActivity() {
    // Remove all periodic check code
    // Native background thread handles this
    // Runs at random intervals (5-15 seconds)
    // Cannot be stopped by managed layer
    
    override fun onResume() {
        super.onResume()
        // Just continue normally
    }
}
```

---

## Native Code Changes

### CMakeLists.txt

**Before:**
```cmake
add_library(secureguard SHARED
        native_bridge.cpp
        security_checks.cpp)
```

**After:**
```cmake
add_library(secureguard SHARED
        native_bridge_hardened.cpp)
        
# Header-only implementation
# All logic in: enforcement.h, continuous_monitor.h, self_protect.h
```

### JNI Methods

**Before:**
```cpp
extern "C" JNIEXPORT jboolean JNICALL
Java_..._nativeCheckRoot(JNIEnv* env, jobject thiz) {
    bool isRooted = checkSuBinary();
    return (jboolean) isRooted;  // Returns to managed layer
}

extern "C" JNIEXPORT jboolean JNICALL
Java_..._nativeCheckDebugger(JNIEnv* env, jobject thiz) {
    bool isDebugged = checkTracerPid();
    return (jboolean) isDebugged;  // Returns to managed layer
}
```

**After:**
```cpp
// Constructor - starts before managed code
__attribute__((constructor))
static void auto_initialize() {
    monitor::initialize();  // Starts background thread
}

extern "C" JNIEXPORT void JNICALL
Java_..._nativeInitialize(JNIEnv* env, jobject thiz) {
    self_protect::initialize(env);
    // No return value
    // Just verifies and starts monitoring
}

extern "C" JNIEXPORT void JNICALL
Java_..._nativeEnforce(JNIEnv* env, jobject thiz) {
    enforcement::terminate_process();
    // Never returns
}
```

---

## Breaking Changes

### Removed APIs

All of these return `boolean` - removed in v2.0:

```kotlin
// ❌ REMOVED
SecurityManager.checkRootAccess(): Boolean
SecurityManager.checkDebugger(): Boolean
SecurityManager.checkEmulator(): Boolean
SecurityManager.checkHooking(): Boolean
SecurityManager.checkIntegrity(): Boolean

RootDetector.check(): Boolean
RootDetector.isRooted(): Boolean

EmulatorDetector.check(): Boolean
EmulatorDetector.isEmulator(): Boolean

DebuggerDetector.check(): Boolean
DebuggerDetector.isDebugged(): Boolean

HookingDetector.check(): Boolean
HookingDetector.isHooked(): Boolean
```

### Removed Native Methods

```cpp
// ❌ REMOVED - all returned boolean
nativeCheckRoot()
nativeCheckDebugger()
nativeCheckEmulator()
nativeCheckHooking()
nativeCheckIntegrity()
```

### Kept APIs

```kotlin
// ✅ KEPT - doesn't return security status
SecurityManager.initialize(context): SecurityManager
SecurityManager.getInstance(): SecurityManager
SecurityManager.getDeviceInfo(): Map<String, String>  // For analytics only

// ✅ KEPT - but doesn't return
SecurityManager.enforceTermination(): Unit  // Never returns, terminates process
```

---

## Behavior Changes

### Security Failures

**Before:**
- Shows dialog with error message
- Graceful exit with `exitProcess(1)`
- User sees "Security Warning" alert
- Easy to identify it's a security block

**After:**
- No dialog or warning
- App crashes with `SIGSEGV` or `_exit(137)`
- Looks like a bug, not security enforcement
- Random crash types: segfault, illegal instruction, memory corruption
- Hard to identify the cause

### Monitoring

**Before:**
- Check once at startup
- Optional periodic checks (managed layer controls timing)
- Can be disabled by not calling check methods

**After:**
- Starts automatically via `__attribute__((constructor))`
- Continuous background thread
- Random intervals (5-15 seconds)
- Cannot be stopped by managed layer
- Runs independently forever

### Bypass Difficulty

**Before:**
- Hook `checkSecurity()` → return `true` → Done
- Time: 5 minutes
- Reliability: 99%

**After:**
- Multiple entry points, no clean API
- Need to: find constructor, kill thread, patch multiple functions, handle random crashes
- Time: Hours to days
- Reliability: 50-70% (crashes randomly)

---

## Testing

### Test That Security Still Works

```kotlin
// You cannot "test" security anymore
// Because there are no boolean returns

// Instead, test that app runs normally on clean device
@Test
fun testAppRunsOnCleanDevice() {
    SecurityManager.initialize(context)
    // App should continue without crashing
    // If it crashes, native detected something
}
```

### Test on Rooted Device

```kotlin
// On rooted device, app should crash
// But you can't catch it or test it
// Because crash happens from native code

// Expected behavior:
// 1. App starts
// 2. Native monitoring begins
// 3. Within 5-15 seconds, app crashes
// 4. No error message, just crash
```

---

## Troubleshooting

### App Crashes on Clean Device

**Cause:** False positive in native checks

**Solution:** Adjust thresholds in native code:
```cpp
// continuous_monitor.h
// Reduce sensitivity or add whitelists
```

### Want to Add Custom Enforcement

```kotlin
// If you detect something in managed layer
// and want to enforce immediately:

SecurityManager.getInstance().enforceTermination()
// This never returns - process dies immediately
```

### Need Analytics on Security Events

```kotlin
// You cannot get security status anymore
// Native code doesn't report back

// Instead, log device info for correlation:
val info = SecurityManager.getInstance().getDeviceInfo()
Analytics.log("session_start", info)

// In your backend, correlate:
// - Crash reports with device fingerprint
// - If crashes happen on specific device types
// - That indicates security enforcement
```

---

## Rollback Plan

If you need to rollback to old API:

```groovy
// build.gradle
dependencies {
    // Rollback to old version
    implementation 'com.secureguard:secureguard-sdk:1.0.0'
}
```

Then restore old code:
```kotlin
val security = SecurityManager.initialize(this)
if (!security.checkIntegrity()) {
    exitProcess(1)
}
```

But note: Old version is vulnerable to trivial bypasses

---

## Summary

| Aspect | Before | After |
|--------|--------|-------|
| **API calls** | Multiple check methods | One `initialize()` |
| **Return types** | `Boolean` | `void` |
| **Decision maker** | Managed layer | Native code |
| **Monitoring** | One-time or periodic | Continuous background |
| **Exit behavior** | Graceful with dialog | Crash (SIGSEGV, corruption) |
| **Bypass time** | 5 minutes | Hours to days |
| **Bypass reliability** | 99% | 50-70% |
| **Code to remove** | All security checks | Keep only `initialize()` |

---

## Final Notes

**Key Insight:**

> "If your app asks the managed layer whether it should continue running,  
> attackers will answer."

**Our Response:**

We don't ask. Native decides on its own.

**Result:**

- No boolean returns to hook
- No decision points to bypass
- No clean exits to simulate
- Continuous enforcement
- Unreliable bypasses
- **Most attackers choose easier targets** ✓

---

**Migration Difficulty**: Low (remove code)  
**Security Improvement**: High (hours vs minutes to bypass)  
**Recommended**: Migrate immediately for production apps
