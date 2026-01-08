#ifndef SECUREGUARD_SECURITY_CHECKS_H
#define SECUREGUARD_SECURITY_CHECKS_H

#include <string>
#include <jni.h>

// EXPERT-PROOF: Compile-time string obfuscation using XOR
// Strings are encrypted at compile-time, decrypted at runtime
#define OBFUSCATE_KEY 0xAB

// Simple compile-time XOR obfuscator for string literals
constexpr char obfuscate_char(char c, size_t idx)
{
    return c ^ (OBFUSCATE_KEY + idx);
}

// Template for compile-time string obfuscation
template <size_t N>
class ObfuscatedString
{
private:
    char data[N];

public:
    constexpr ObfuscatedString(const char *str) : data{}
    {
        for (size_t i = 0; i < N - 1; ++i)
        {
            data[i] = obfuscate_char(str[i], i);
        }
        data[N - 1] = '\0';
    }

    std::string decrypt() const
    {
        std::string result;
        result.reserve(N);
        for (size_t i = 0; i < N - 1; ++i)
        {
            result += data[i] ^ (OBFUSCATE_KEY + i);
        }
        return result;
    }
};

// Macro for easy string obfuscation
#define OBFSTR(str) ([]() { \
    constexpr ObfuscatedString<sizeof(str)> obf(str); \
    return obf.decrypt(); }())

/**
 * Security check implementations in native code
 * EXPERT-PROOF: Native owns enforcement, not reporting
 * All critical strings are obfuscated at compile-time
 */
class SecurityChecks
{
public:
    /**
     * Check if device is rooted
     * EXPERT-PROOF: Enforces directly on detection, no return value matters
     */
    static bool isRooted();

    /**
     * Check if running on emulator
     * EXPERT-PROOF: Enforces directly on detection, no return value matters
     */
    static bool isEmulator();

    /**
     * Check if debugger is attached
     * EXPERT-PROOF: Enforces directly on detection, no return value matters
     */
    static bool isDebuggerAttached();

    /**
     * Check if Frida is present
     * EXPERT-PROOF: Enforces directly on detection, no return value matters
     */
    static bool isFridaDetected();

    /**
     * Check if developer mode/ADB is enabled
     * EXPERT-PROOF: Enforces directly on detection, runs autonomously
     */
    static bool isDeveloperModeEnabled();

    /**
     * Check developer mode by reading Settings.Global from native (UNHOOKABLE)
     * Uses JNI to call Android Settings API directly from C++
     * Bypasses any Kotlin/Java hooks
     */
    static void checkDeveloperModeFromNative(JavaVM *vm);

    /**
     * Report developer mode status from Kotlin layer
     * Kotlin reads Settings.Global.DEVELOPMENT_SETTINGS_ENABLED and passes result here
     * Native enforces immediately if enabled
     */
    static void reportDeveloperMode(bool enabled);

    /**
     * Get device fingerprint
     */
    static std::string getDeviceFingerprint();

    /**
     * EXPERT-PROOF: Start autonomous security monitoring
     * Uses direct syscalls (unhookable), 3 redundant threads, library integrity checks
     */
    static void startAutonomousMonitoring();

    /**
     * Stop autonomous monitoring (for testing only)
     */
    static void stopAutonomousMonitoring();

    /**
     * Enforce security violation - Native owns the consequence
     * PENTESTER-PROOF: No return to Java, direct termination
     */
    static void enforceSecurityViolation(const char *reason);

private:
    /**
     * Check for SU binary
     */
    static bool checkSuBinary();

    /**
     * Check /proc/self/maps for suspicious libraries
     */
    static bool checkMapsForLibrary(const char *library);

    /**
     * Check /proc/self/status for TracerPid
     */
    static bool checkTracerPid();

    /**
     * Read file content
     */
    static std::string readFile(const char *path);
};

#endif // SECUREGUARD_SECURITY_CHECKS_H
