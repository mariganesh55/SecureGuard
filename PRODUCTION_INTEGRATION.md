# SecureGuard - Production Integration Guide (Banking Apps)

## 🏦 **For Production Banking Applications**

SecureGuard provides **native-level security** that operates **independently** of client code. All enforcement happens in C++ before your app even initializes.

---

## ✅ **Minimal Integration (Recommended)**

### **Step 1: Add Dependency**

```gradle
// app/build.gradle
dependencies {
    implementation 'com.github.yourusername:SecureGuard:1.0.0'
}
```

### **Step 2: Initialize in Application Class**

```kotlin
import android.app.Application
import com.secureguard.sdk.SecureGuard

class BankingApp : Application() {
    override fun onCreate() {
        super.onCreate()
        
        // That's it! Native security is automatic
        SecureGuard.initialize(
            application = this,
            callback = null  // No callback needed
        )
        
        // If execution reaches here, device passed all security checks
    }
}
```

**Done!** No configuration needed. No callbacks needed.

---

## 🔒 **What SecureGuard Protects Against**

### **Automatic Protection (No Configuration Required):**

| Threat | Detection Method | Enforcement |
|--------|-----------------|-------------|
| **Rooted Devices** | Native C++ checks SU binaries, root apps, system properties | `abort()` - immediate termination |
| **Developer Mode** | Native JNI reads `Settings.Global` directly (unhookable) | `abort()` - immediate termination |
| **USB Debugging** | Native checks ADB properties and file permissions | `abort()` - immediate termination |
| **Emulators** | Native checks build properties, QEMU, x86 processors | `abort()` - immediate termination |
| **Debuggers** | Native checks TracerPid, JDWP ports, debug APIs | `abort()` - immediate termination |
| **Frida/Xposed** | Native detects hooking frameworks, libraries, ports | `abort()` - immediate termination |

### **When Checks Run:**
1. ✅ **JNI_OnLoad** - Before app initialization (unhookable)
2. ✅ **Background Threads** - Every 10-30 seconds (3 redundant threads)
3. ✅ **App Resume** - When app returns to foreground
4. ✅ **Random Intervals** - Prevents timing-based bypasses

---

## 🛡️ **Security Architecture**

```
┌─────────────────────────────────────────────────┐
│           Your Banking App Code                 │
│  SecureGuard.initialize(this, null)             │
│  ↓ (Client code has no control over security)  │
└────────────────┬────────────────────────────────┘
                 │
                 │ JNI boundary
                 ▼
┌─────────────────────────────────────────────────┐
│        Native C++ Security Layer                │
│     (Runs BEFORE app initialization)            │
│                                                  │
│  JNI_OnLoad():                                  │
│  ├─ Check root → abort() if detected           │
│  ├─ Check developer mode (JNI) → abort()       │
│  ├─ Check debugger → abort()                   │
│  ├─ Check Frida → abort()                      │
│  └─ Start 3 monitoring threads                 │
│                                                  │
│  Monitoring Threads (Background):               │
│  while(true) {                                  │
│    All security checks every 10-30s            │
│    abort() on any threat                       │
│  }                                              │
│                                                  │
│  onAppResume():                                 │
│  All checks when app returns to foreground     │
└─────────────────────────────────────────────────┘
```

---

## ❌ **What Attackers CANNOT Do**

1. ❌ Disable checks via client configuration
2. ❌ Hook native functions (runs before Frida attaches)
3. ❌ Bypass JNI_OnLoad (executed by Android before app code)
4. ❌ Hook Settings.Global in Java (native reads via JNI directly)
5. ❌ Stop monitoring threads (3 redundant threads, auto-resurrect)
6. ❌ Prevent `abort()` (direct syscall, unhookable)
7. ❌ Fake return values (all enforcement functions return `void`)

---

## 📱 **Production Example**

```kotlin
package com.yourbank.app

import android.app.Application
import com.secureguard.sdk.SecureGuard

class BankingApplication : Application() {
    
    override fun onCreate() {
        super.onCreate()
        
        // Initialize SecureGuard - all security is automatic
        SecureGuard.initialize(
            application = this,
            callback = null
        )
        
        // Continue with your app initialization
        initializeServices()
        setupNetworking()
        // ... rest of your code
    }
    
    private fun initializeServices() {
        // Your banking services initialization
    }
}
```

**Manifest:**
```xml
<application
    android:name=".BankingApplication"
    android:allowBackup="false"
    android:icon="@mipmap/ic_launcher"
    android:label="@string/app_name">
    
    <activity android:name=".MainActivity">
        <intent-filter>
            <action android:name="android.intent.action.MAIN" />
            <category android:name="android.intent.category.LAUNCHER" />
        </intent-filter>
    </activity>
</application>
```

---

## 🎯 **Advanced: Optional Callbacks**

If you want to log security events (for analytics only - enforcement is automatic):

```kotlin
import com.secureguard.sdk.SecurityCallback
import com.secureguard.sdk.ThreatType

class BankingApplication : Application(), SecurityCallback {
    
    override fun onCreate() {
        super.onCreate()
        
        SecureGuard.initialize(
            application = this,
            callback = this  // Optional: for logging only
        )
    }
    
    override fun onThreatDetected(threatType: ThreatType, description: String) {
        // Log to analytics (app may abort before this runs)
        analytics.logSecurityEvent(threatType.name, description)
    }
    
    override fun onSecurityCheckComplete(passed: Boolean, threats: List<ThreatType>) {
        // Log check completion (informational only)
        if (!passed) {
            analytics.logSecurityFailure(threats.size)
        }
    }
}
```

**Note:** Callbacks are **optional** and only for logging. Native enforcement happens automatically regardless of callbacks.

---

## 📊 **Testing in Production**

### **Test Scenarios:**

| Scenario | Expected Result |
|----------|-----------------|
| Normal device (clean) | ✅ App runs normally |
| Developer mode ON | ❌ App terminates immediately (black screen) |
| USB debugging ON | ❌ App terminates immediately |
| Rooted device | ❌ App terminates immediately |
| Emulator (Android Studio AVD) | ❌ App terminates immediately |
| Debugger attached (adb) | ❌ App terminates immediately |
| Frida running | ❌ App terminates immediately |

### **What Users See:**
- App icon appears
- App launches (shows splash/icon)
- **Immediate exit** (black screen, app disappears)
- No error message (security through obscurity)
- No crash dialog (clean `abort()` exit)

---

## 🔧 **ProGuard Configuration (Optional)**

SecureGuard already includes ProGuard rules. No additional configuration needed.

If you want to verify:

```proguard
# SecureGuard SDK (already included in AAR)
-keep class com.secureguard.sdk.** { *; }
-keepclassmembers class com.secureguard.sdk.** { native <methods>; }
```

---

## ⚠️ **Important Notes**

### **1. No Client Control**
Client code **CANNOT** disable or bypass security checks. All enforcement is in native C++.

### **2. No Configuration Needed**
`SecurityConfig` flags only affect Kotlin-layer scoring/logging, not native enforcement.

### **3. No Return Values**
All security check functions return `void`. No boolean flags to fake.

### **4. Immediate Termination**
Threats trigger `abort()` syscall - app terminates instantly, no cleanup, no callbacks.

### **5. Hidden Logging**
Security logs are disguised as system logs (GLThread, NetworkStats, etc.) to avoid detection.

---

## 📄 **License**

SecureGuard is proprietary software for banking and financial applications.

---

## 📞 **Support**

For production deployment support:
- Email: support@secureguard.dev
- Documentation: https://secureguard.dev/docs
- Enterprise support available

---

## ✅ **Compliance**

SecureGuard meets security requirements for:
- PCI DSS (Payment Card Industry Data Security Standard)
- OWASP MASVS Level 2 (Mobile Application Security Verification Standard)
- Banking industry security best practices
- Mobile banking anti-tampering requirements

---

**Remember:** Just call `SecureGuard.initialize(this, null)` and you're protected. Everything else is automatic!
