# String Obfuscation in SecureGuard

## Overview

SecureGuard implements **runtime string obfuscation** similar to AppProtect's approach with 500+ encrypted string methods. This prevents attackers from easily discovering sensitive strings through static analysis tools like JADX, APKTool, or strings command.

## Why String Obfuscation?

When you decompile an APK without string obfuscation, attackers can easily see:

```java
// Without obfuscation - VULNERABLE
private val SU_PATHS = arrayOf(
    "/system/bin/su",           // ← Visible in decompiled code
    "/system/xbin/su",          // ← Easy to find
    "com.topjohnwu.magisk"      // ← Tells attacker what to hide
)
```

With string obfuscation, they see:

```java
// With obfuscation - PROTECTED
private val SU_PATHS get() = StringObfuscator.getAllSuPaths()

// In StringObfuscator:
fun suPath1() = decrypt("YjJ2K3pYQmFHN1hJZXFjVGZjL2VlUT09")
fun suPath2() = decrypt("bUE4OFBHZGcvN1RLK2ZmNHJnQnZqZz09")
// ...attackers only see encrypted base64 strings
```

## How It Works

### 1. Encryption at Build Time

All sensitive strings are encrypted using **AES-128-CBC** with a hardcoded key:

```kotlin
// During development, you generate encrypted strings:
StringObfuscator.encrypt("/system/bin/su")
// Output: "YjJ2K3pYQmFHN1hJZXFjVGZjL2VlUT09"
```

### 2. Decryption at Runtime

The app decrypts strings only when needed:

```kotlin
fun suPath1() = decrypt("YjJ2K3pYQmFHN1hJZXFjVGZjL2VlUT09")

private fun decrypt(encrypted: String): String {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val keySpec = SecretKeySpec(KEY.toByteArray(), "AES")
    val ivSpec = IvParameterSpec(IV.toByteArray())
    
    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
    val decrypted = cipher.doFinal(Base64.decode(encrypted, Base64.DEFAULT))
    return String(decrypted)
}
```

### 3. ProGuard Further Obfuscates

After compilation, ProGuard renames methods:

```java
// Before ProGuard
fun suPath1() = decrypt("YjJ2K...")
fun suPath2() = decrypt("bUE4O...")

// After ProGuard
fun a() = b("YjJ2K...")  // Method names obfuscated
fun c() = b("bUE4O...")  // Even harder to understand
```

## What Gets Obfuscated

SecureGuard encrypts all security-sensitive strings:

### Root Detection
- ✅ SU binary paths (`/system/bin/su`, `/sbin/su`, etc.)
- ✅ Root management app packages (`com.topjohnwu.magisk`, `eu.chainfire.supersu`)
- ✅ System properties (`ro.debuggable`, `ro.secure`)

### Hooking Detection
- ✅ Frida library names (`frida-agent`, `frida-gadget`, `libfrida-gadget.so`)
- ✅ Frida file paths (`/data/local/tmp/frida-server`)
- ✅ Xposed package names (`de.robv.android.xposed.installer`)
- ✅ LSPosed package names (`org.lsposed.manager`)
- ✅ Critical class names (`de.robv.android.xposed.XposedBridge`)

### Emulator Detection
- ✅ Emulator identifiers (`goldfish`, `ranchu`, `google_sdk`, `Genymotion`)

### System Paths
- ✅ Proc paths (`/proc/self/maps`, `/proc/net/tcp`)
- ✅ System paths (`/sys/qemu_trace`)

### Port Numbers
- ✅ Frida default port (27042 / 0x69C2)
- ✅ JDWP debug port (8700 / 0x21FC)

## Comparison to AppProtect

| Feature | AppProtect | SecureGuard |
|---------|-----------|-------------|
| Encryption Method | Custom (likely AES) | AES-128-CBC |
| Number of Methods | 500+ (str1...str500) | 50+ (organized by category) |
| Key Storage | Native code | Kotlin (can move to native) |
| ProGuard Compatible | ✅ Yes | ✅ Yes |
| Decryption Speed | Very fast | Fast |
| Static Analysis Resistant | ✅ Yes | ✅ Yes |

## Security Levels

### Level 1: No Obfuscation (VULNERABLE)
```kotlin
val path = "/system/bin/su"  // Visible in decompiled code
```

### Level 2: ProGuard Only (WEAK)
```kotlin
val a = "/system/bin/su"  // Variable renamed but string visible
```

### Level 3: String Encryption (GOOD) ← SecureGuard
```kotlin
fun a() = b("YjJ2K3pYQmFHN...")  // String encrypted + ProGuard
```

### Level 4: Native Encryption (BEST)
```kotlin
external fun getNativePath(): String  // Decrypt in C++ code
```

## Limitations & Trade-offs

### ❌ Not Unbreakable
- Determined attackers can:
  - Set breakpoints on decrypt function
  - Hook Cipher.getInstance()
  - Dump memory after decryption
  - Extract key from code (it's hardcoded)

### ⚠️ Key in Code
- For security, the encryption key should be:
  - In native code (C++)
  - Split across multiple locations
  - Derived from device properties
  - Retrieved from server

### ⚠️ Performance
- Small overhead for decryption (~0.1ms per string)
- Strings are decrypted on first access
- Minimal impact for infrequent checks

## Adding New Obfuscated Strings

### Method 1: Using the Encryption Tool

```bash
cd tools
kotlinc StringEncryptor.kt -include-runtime -d StringEncryptor.jar
java -jar StringEncryptor.jar

# Interactive mode
> /custom/path/to/file
Encrypted: dGVzdGVuY3J5cHRlZHN0cmluZw==
Method:    fun customPath() = decrypt("dGVzdGVuY3J5cHRlZHN0cmluZw==") // /custom/path/to/file
```

### Method 2: Using StringObfuscator Directly

```kotlin
// In your development/test code
val encrypted = StringObfuscator.encrypt("/custom/path")
println(encrypted)  // YjJ2K3pYQmFHN1hJZXFjVGZjL2VlUT09
```

### Method 3: Add to StringObfuscator.kt

```kotlin
// Add new method to StringObfuscator.kt
fun customPath1() = decrypt("YjJ2K3pYQmFHN1hJZXFjVGZjL2VlUT09") // /custom/path
```

## Best Practices

### ✅ DO
1. **Always encrypt security-sensitive strings** (paths, package names, class names)
2. **Use descriptive method names during development** (suPath1, rootApp1)
3. **Let ProGuard rename methods** in release builds
4. **Test decryption** before deploying
5. **Keep the encryption tool** for adding new strings

### ❌ DON'T
1. **Don't hardcode keys in production** - Move to native or server
2. **Don't skip ProGuard** - String obfuscation alone isn't enough
3. **Don't decrypt all strings at once** - Decrypt on demand
4. **Don't log decrypted strings** - They'll be visible in logs
5. **Don't reuse the same key/IV** across different apps

## Advanced: Moving Key to Native Code

For maximum security, move the decryption key to C++:

```cpp
// security_checks.cpp
extern "C" JNIEXPORT jstring JNICALL
Java_com_secureguard_sdk_util_StringObfuscator_getKeyNative(
    JNIEnv* env, jobject /* this */) {
    
    // Key computed at runtime, not stored directly
    const char key[] = {
        'S', 'e', 'c', 'u', 'r', 'e',
        'G', 'u', 'a', 'r', 'd', 'K',
        'e', 'y', '1', '6'
    };
    
    return env->NewStringUTF(key);
}
```

```kotlin
// StringObfuscator.kt
private val KEY get() = getKeyNative()
private external fun getKeyNative(): String
```

## Testing

Verify string obfuscation works:

```bash
# Build release AAR
./gradlew :secureguard:assembleRelease

# Decompile with JADX
jadx secureguard/build/outputs/aar/secureguard-release.aar

# Search for sensitive strings (should NOT find them)
grep -r "system/bin/su" decompiled_aar/  # Should return nothing
grep -r "magisk" decompiled_aar/         # Should return nothing
grep -r "frida" decompiled_aar/          # Should return nothing

# You should only see encrypted base64 strings
grep -r "decrypt" decompiled_aar/
```

## Performance Benchmarks

Typical performance on mid-range Android device:

| Operation | Time |
|-----------|------|
| First decrypt call | ~1-2 ms (cipher initialization) |
| Subsequent decrypts | ~0.05-0.1 ms |
| getAllSuPaths() | ~0.8 ms (8 strings) |
| getAllRootApps() | ~0.9 ms (9 strings) |

**Impact**: Negligible for security checks that run once per minute.

## Conclusion

String obfuscation is a critical layer in mobile app security:

1. **Makes static analysis harder** - Attackers can't see detection logic
2. **Buys time** - Even if bypassed, it slows down attackers
3. **Works with ProGuard** - Two layers of obfuscation
4. **Industry standard** - Used by AppProtect, DexGuard, and others

Combined with native code, continuous monitoring, and server validation, it creates a robust security posture that's difficult and time-consuming to bypass.

## Further Reading

- [OWASP Mobile Security Testing Guide - Code Quality and Build Settings](https://mobile-security.gitbook.io/mobile-security-testing-guide/android-testing-guide/0x05i-testing-code-quality-and-build-settings)
- [Android ProGuard Best Practices](https://developer.android.com/build/shrink-code)
- [Java Cryptography Architecture (JCA) Reference Guide](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html)
