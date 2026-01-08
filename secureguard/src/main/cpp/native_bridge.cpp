#include <jni.h>
#include <string>
#include <android/log.h>
#include "security_checks.h"

#define LOG_TAG "SecureGuard-Native"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern "C"
{

    /**
     * PENTESTER-PROOF: JNI_OnLoad - Start autonomous monitoring
     * Runs BEFORE any Java code can hook it
     * CRITICAL: Immediate security checks prevent app from loading if threats detected
     */
    JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
    {
        LOGD("🔒 JNI_OnLoad called - Performing immediate security checks");

        // CRITICAL: Do immediate checks BEFORE starting threads or allowing app to load
        // This prevents the app from even initializing if developer mode/root/etc is detected
        SecurityChecks::isRooted();

        // Check developer mode by reading Settings.Global from native (unhookable)
        // Also stores JavaVM for periodic checks
        SecurityChecks::checkDeveloperModeFromNative(vm);

        SecurityChecks::isDebuggerAttached();
        SecurityChecks::isFridaDetected();

        // Start autonomous monitoring threads for continuous checking (includes periodic dev mode checks)
        SecurityChecks::startAutonomousMonitoring();
        SecurityChecks::startAutonomousMonitoring();

        LOGD("✅ Native library initialized - Autonomous monitoring active");
        return JNI_VERSION_1_6;
    } /**
       * Initialize native library
       * PENTESTER-PROOF: This is now redundant - monitoring already started in JNI_OnLoad
       */
    JNIEXPORT void JNICALL
    Java_com_secureguard_sdk_core_NativeSecurityBridge_initNative(
        JNIEnv *env,
        jobject /* this */)
    {
        LOGD("Native library initialized");
        // Monitoring already running from JNI_OnLoad
    }

    /**
     * EXPERT-PROOF: Check for root - NO RETURN VALUE
     * Runs check autonomously, app will crash if threats detected
     * Pentester can hook this, but autonomous threads will still enforce
     */
    JNIEXPORT void JNICALL
    Java_com_secureguard_sdk_core_NativeSecurityBridge_checkRootNative(
        JNIEnv *env,
        jobject /* this */)
    {
        // Just trigger the check - enforcement is autonomous
        SecurityChecks::isRooted();
        // No return value to fake
    }

    /**
     * EXPERT-PROOF: Check for emulator - NO RETURN VALUE
     * Runs check autonomously, app will crash if threats detected
     */
    JNIEXPORT void JNICALL
    Java_com_secureguard_sdk_core_NativeSecurityBridge_checkEmulatorNative(
        JNIEnv *env,
        jobject /* this */)
    {
        // Just trigger the check - enforcement is autonomous
        SecurityChecks::isEmulator();
        // No return value to fake
    }

    /**
     * EXPERT-PROOF: Check for debugger - NO RETURN VALUE
     * Runs check autonomously, app will crash if threats detected
     */
    JNIEXPORT void JNICALL
    Java_com_secureguard_sdk_core_NativeSecurityBridge_checkDebuggerNative(
        JNIEnv *env,
        jobject /* this */)
    {
        // Just trigger the check - enforcement is autonomous
        SecurityChecks::isDebuggerAttached();
        // No return value to fake
    }

    /**
     * EXPERT-PROOF: Check for Frida - NO RETURN VALUE
     * Runs check autonomously, app will crash if threats detected
     */
    JNIEXPORT void JNICALL
    Java_com_secureguard_sdk_core_NativeSecurityBridge_checkFridaNative(
        JNIEnv *env,
        jobject /* this */)
    {
        // Just trigger the check - enforcement is autonomous
        SecurityChecks::isFridaDetected();
        // No return value to fake
    }

    /**
     * EXPERT-PROOF: Direct enforcement trigger
     * Kotlin calls this when it detects a threat
     * Immediately enforces security violation
     */
    JNIEXPORT void JNICALL
    Java_com_secureguard_sdk_core_NativeSecurityBridge_enforceViolation(
        JNIEnv *env,
        jobject /* this */,
        jstring reason)
    {
        const char *reasonStr = env->GetStringUTFChars(reason, nullptr);

        // Directly call enforcement
        SecurityChecks::enforceSecurityViolation(reasonStr);

        env->ReleaseStringUTFChars(reason, reasonStr);
        // If we reach here, enforcement didn't kill the app (shouldn't happen)
    }

    /**
     * EXPERT-PROOF: Perform comprehensive check - NO RETURN VALUE
     * All enforcement happens autonomously in background threads
     * Pentester can hook this entire function - doesn't matter!
     */
    JNIEXPORT void JNICALL
    Java_com_secureguard_sdk_core_NativeSecurityBridge_performEnvironmentCheck(
        JNIEnv *env,
        jobject /* this */)
    {
        // Just trigger all checks - enforcement is autonomous
        SecurityChecks::isRooted();
        SecurityChecks::isEmulator();
        SecurityChecks::isDebuggerAttached();
        SecurityChecks::isFridaDetected();
        // No return value to fake
        // No risk score to manipulate
        // Autonomous threads will enforce independently
    }

    /**
     * Get device fingerprint
     */
    JNIEXPORT jstring JNICALL
    Java_com_secureguard_sdk_core_NativeSecurityBridge_getDeviceFingerprint(
        JNIEnv *env,
        jobject /* this */)
    {
        std::string fingerprint = SecurityChecks::getDeviceFingerprint();
        return env->NewStringUTF(fingerprint.c_str());
    }

    /**
     * Report developer mode status from Kotlin
     * Kotlin reads Settings.Global.DEVELOPMENT_SETTINGS_ENABLED and passes result here
     * Native enforces immediately if enabled
     * EXPERT-PROOF: Enforcement happens in native, Kotlin just provides the flag
     */
    JNIEXPORT void JNICALL
    Java_com_secureguard_sdk_core_NativeSecurityBridge_reportDeveloperMode(
        JNIEnv *env,
        jobject /* this */,
        jboolean enabled)
    {
        SecurityChecks::reportDeveloperMode(enabled);
        // If we reach here, developer mode was not enabled (or enforcement failed)
    }

    /**
     * Called when app resumes - performs all security checks again
     * PENTESTER-PROOF: Re-checks everything including developer mode via JNI
     */
    JNIEXPORT void JNICALL
    Java_com_secureguard_sdk_core_NativeSecurityBridge_onAppResume(
        JNIEnv *env,
        jobject /* this */)
    {
        LOGD("App resumed - performing security checks");

        // Get JavaVM from environment
        JavaVM *vm = nullptr;
        env->GetJavaVM(&vm);

        if (vm != nullptr)
        {
            // Check developer mode using JNI (reads Settings.Global directly)
            SecurityChecks::checkDeveloperModeFromNative(vm);
        }

        // Trigger all other checks
        SecurityChecks::isRooted();
        SecurityChecks::isDebuggerAttached();
        SecurityChecks::isFridaDetected();

        LOGD("Resume security checks complete");
    }
} // extern "C"
