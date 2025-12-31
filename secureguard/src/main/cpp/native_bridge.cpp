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
     */
    JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
    {
        LOGD("JNI_OnLoad called - Starting autonomous security");

        // Start autonomous monitoring thread immediately
        // PENTESTER-PROOF: Runs independently of Java layer
        SecurityChecks::startAutonomousMonitoring();

        return JNI_VERSION_1_6;
    }

    /**
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

} // extern "C"
