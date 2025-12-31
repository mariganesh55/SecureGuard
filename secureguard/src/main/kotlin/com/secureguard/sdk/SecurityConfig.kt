package com.secureguard.sdk

/**
 * Configuration for SecureGuard security features
 */
data class SecurityConfig(
    /**
     * Enable root detection
     */
    val enableRootDetection: Boolean = true,
    
    /**
     * Enable emulator detection
     */
    val enableEmulatorDetection: Boolean = true,
    
    /**
     * Enable debugger detection
     */
    val enableDebuggerDetection: Boolean = true,
    
    /**
     * Enable hooking framework detection (Frida, Xposed, etc.)
     */
    val enableHookingDetection: Boolean = true,
    
    /**
     * Enable APK integrity checks (signature verification)
     */
    val enableIntegrityChecks: Boolean = true,
    
    /**
     * Expected APK signature hash (SHA-256)
     * Leave null to skip signature validation, set to verify against specific signature
     */
    val expectedSignatureHash: String? = null,
    
    /**
     * Enable screen recording/screenshot detection
     */
    val enableScreenSecurityChecks: Boolean = true,
    
    /**
     * Enable accessibility service threat detection
     */
    val enableAccessibilityChecks: Boolean = true,
    
    /**
     * Block app execution on threat detection
     */
    val blockOnThreat: Boolean = false,
    
    /**
     * Show alert dialog on threat detection
     */
    val showAlertOnThreat: Boolean = true,
    
    /**
     * Custom message for security alert
     */
    val alertMessage: String = "Security threat detected. This app cannot run on compromised devices.",
    
    /**
     * Enable continuous security monitoring
     */
    val enableContinuousMonitoring: Boolean = false,
    
    /**
     * Continuous monitoring interval in seconds (default: 1800 = 30 minutes)
     * Only applies if enableContinuousMonitoring is true
     */
    val monitoringIntervalSeconds: Long = 1800L,
    
    /**
     * Re-check security when app comes to foreground
     */
    val checkOnAppResume: Boolean = true
) {
    companion object {
        /**
         * Maximum security configuration (Banking-grade)
         */
        fun maximumSecurity() = SecurityConfig(
            enableRootDetection = true,
            enableEmulatorDetection = true,
            enableDebuggerDetection = true,
            enableHookingDetection = true,
            enableIntegrityChecks = true,
            enableScreenSecurityChecks = true,
            enableAccessibilityChecks = true,
            blockOnThreat = true,
            showAlertOnThreat = true,
            enableContinuousMonitoring = true,
            monitoringIntervalSeconds = 1800L, // 30 minutes
            checkOnAppResume = true
        )
        
        /**
         * Development-friendly configuration
         */
        fun developmentMode() = SecurityConfig(
            enableRootDetection = false,
            enableEmulatorDetection = false,
            enableDebuggerDetection = false,
            enableHookingDetection = false,
            enableIntegrityChecks = false,
            enableScreenSecurityChecks = false,
            enableAccessibilityChecks = false,
            blockOnThreat = false,
            showAlertOnThreat = false,
            enableContinuousMonitoring = false
        )
        
        /**
         * Production configuration with balanced security
         */
        fun productionMode() = SecurityConfig(
            enableRootDetection = true,
            enableEmulatorDetection = true,
            enableDebuggerDetection = true,
            enableHookingDetection = true,
            enableIntegrityChecks = true,
            enableScreenSecurityChecks = true,
            enableAccessibilityChecks = true,
            blockOnThreat = true,
            showAlertOnThreat = true,
            enableContinuousMonitoring = true,
            monitoringIntervalSeconds = 1800L, // 30 minutes
            checkOnAppResume = true
        )
    }
}
