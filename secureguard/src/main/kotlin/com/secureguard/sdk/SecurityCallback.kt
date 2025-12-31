package com.secureguard.sdk

/**
 * Callback interface for security events
 */
interface SecurityCallback {
    
    /**
     * Called when a security threat is detected
     * 
     * @param threatType Type of threat detected
     * @param description Detailed description of the threat
     */
    fun onThreatDetected(threatType: ThreatType, description: String)
    
    /**
     * Called when security check is complete
     * 
     * @param passed True if all security checks passed
     * @param threats List of detected threats (empty if passed)
     */
    fun onSecurityCheckComplete(passed: Boolean, threats: List<ThreatType>)
    
    /**
     * Called when app should be terminated due to security threat
     */
    fun onAppShouldTerminate() {
        // Default implementation - can be overridden
    }
}
