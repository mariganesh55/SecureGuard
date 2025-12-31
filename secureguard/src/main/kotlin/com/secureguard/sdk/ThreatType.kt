package com.secureguard.sdk

/**
 * Types of security threats that can be detected
 */
enum class ThreatType(val description: String) {
    /**
     * Device is rooted/jailbroken
     */
    ROOT_DETECTED("Device is rooted"),
    
    /**
     * Running on an emulator
     */
    EMULATOR_DETECTED("Running on emulator"),
    
    /**
     * Debugger is attached
     */
    DEBUGGER_DETECTED("Debugger attached"),
    
    /**
     * Hooking framework detected (Frida, Xposed, etc.)
     */
    HOOKING_DETECTED("Hooking framework detected"),
    
    /**
     * App is being tampered with
     */
    TAMPERING_DETECTED("App tampering detected"),
    
    /**
     * APK signature is invalid or modified
     */
    INVALID_SIGNATURE("Invalid APK signature - app may be repackaged"),
    
    /**
     * App not installed from legitimate source
     */
    INVALID_INSTALLER("Invalid installer - app not from Play Store"),
    
    /**
     * APK file has been modified after installation
     */
    APK_MODIFIED("APK file modified - possible tampering"),
    
    /**
     * Screen recording is active
     */
    SCREEN_RECORDING_DETECTED("Screen recording detected"),
    
    /**
     * Screenshot was recently taken
     */
    SCREENSHOT_DETECTED("Screenshot detected"),
    
    /**
     * Screen is being mirrored
     */
    SCREEN_MIRRORING_DETECTED("Screen mirroring detected"),
    
    /**
     * Suspicious accessibility service detected
     */
    ACCESSIBILITY_THREAT("Malicious accessibility service detected"),
    
    /**
     * Overlay attack capability detected
     */
    OVERLAY_ATTACK("Overlay attack capability detected"),
    
    /**
     * SSL certificate pinning failed
     */
    SSL_PINNING_FAILED("SSL certificate pinning failed - possible MITM attack"),
    
    /**
     * Unknown threat
     */
    UNKNOWN("Unknown threat detected")
}
