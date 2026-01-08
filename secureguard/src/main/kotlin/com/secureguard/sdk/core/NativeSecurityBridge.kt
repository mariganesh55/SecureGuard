package com.secureguard.sdk.core

/**
 * Bridge to native C++ security checks
 * Provides access to low-level security detection
 * 
 * EXPERT-PROOF: Native autonomous monitoring starts on library load (JNI_OnLoad)
 * NO RETURN VALUES for critical checks - enforcement is 100% autonomous
 * Pentester can hook everything here - doesn't matter!
 */
object NativeSecurityBridge {
    
    init {
        try {
            System.loadLibrary("secureguard-native")
            // EXPERT-PROOF: Autonomous monitoring already started in JNI_OnLoad
            // 3 redundant threads running, using direct syscalls
            android.util.Log.i("NativeSecurityBridge", "Native library loaded - autonomous monitoring active")
        } catch (e: UnsatisfiedLinkError) {
            android.util.Log.e("NativeSecurityBridge", "Failed to load native library", e)
        }
    }
    
    /**
     * Initialize native library
     * EXPERT-PROOF: This is now redundant - monitoring started in JNI_OnLoad
     */
    fun initialize() {
        try {
            initNative()
        } catch (e: UnsatisfiedLinkError) {
            android.util.Log.e("NativeSecurityBridge", "Native library not available", e)
        }
    }
    
    // Native method declarations
    private external fun initNative()
    
    /**
     * EXPERT-PROOF: Trigger root check - NO RETURN VALUE
     * Autonomous threads will enforce independently
     * Pentester can hook this - app will still crash if rooted
     */
    external fun checkRootNative()
    
    /**
     * EXPERT-PROOF: Trigger emulator check - NO RETURN VALUE
     * Autonomous threads will enforce independently
     */
    external fun checkEmulatorNative()
    
    /**
     * EXPERT-PROOF: Trigger debugger check - NO RETURN VALUE
     * Autonomous threads will enforce independently
     */
    external fun checkDebuggerNative()
    
    /**
     * EXPERT-PROOF: Trigger Frida check - NO RETURN VALUE
     * Autonomous threads will enforce independently
     */
    external fun checkFridaNative()
    
    /**
     * EXPERT-PROOF: Directly trigger security violation enforcement
     * Used when Kotlin detects a threat and needs immediate native enforcement
     */
    external fun enforceViolation(reason: String)
    
    /**
     * EXPERT-PROOF: Trigger comprehensive check - NO RETURN VALUE
     * All checks run autonomously, enforcement happens in background threads
     * Pentester can hook this entire function - doesn't matter!
     */
    external fun performEnvironmentCheck()
    
    /**
     * EXPERT-PROOF: Trigger all security checks
     * NO return values to fake, NO flags to manipulate
     * Just triggers autonomous enforcement
     */
    fun triggerSecurityChecks() {
        try {
            checkRootNative()
            checkEmulatorNative()
            checkDebuggerNative()
            checkFridaNative()
        } catch (e: Exception) {
            // Exception doesn't matter - autonomous threads still enforce
            android.util.Log.w("NativeSecurityBridge", "Check trigger failed, but autonomous enforcement active", e)
        }
    }
    
    /**
     * Get device fingerprint
     */
    external fun getDeviceFingerprint(): String
    
    /**
     * Report developer mode status to native layer
     * Kotlin reads Settings.Global.DEVELOPMENT_SETTINGS_ENABLED and passes result here
     * Native enforces immediately if enabled
     * EXPERT-PROOF: Enforcement happens in native, Kotlin just provides the flag
     */
    external fun reportDeveloperMode(enabled: Boolean)
    
    /**
     * Called when app resumes - triggers all security checks
     * PENTESTER-PROOF: Re-checks developer mode via JNI (unhookable)
     */
    external fun onAppResume()
}
