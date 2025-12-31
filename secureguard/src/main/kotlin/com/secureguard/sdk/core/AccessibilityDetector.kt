package com.secureguard.sdk.core

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.provider.Settings
import android.view.accessibility.AccessibilityManager

/**
 * Accessibility Service Detection
 * Detects malicious accessibility services that can:
 * - Read screen content
 * - Perform clicks/taps
 * - Steal credentials
 * - Perform overlay attacks
 * 
 * Critical for banking apps to prevent automated attacks
 */
object AccessibilityDetector {
    
    private const val TAG = "AccessibilityDetector"
    
    /**
     * Check if any accessibility services are enabled
     * Banking apps should be cautious about enabled accessibility services
     */
    fun isAccessibilityServiceEnabled(context: Context): Boolean {
        return try {
            val accessibilityEnabled = Settings.Secure.getInt(
                context.contentResolver,
                Settings.Secure.ACCESSIBILITY_ENABLED,
                0
            )
            
            accessibilityEnabled == 1
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Accessibility check failed", e)
            false
        }
    }
    
    /**
     * Get list of all enabled accessibility services
     */
    fun getEnabledAccessibilityServices(context: Context): List<AccessibilityServiceInfo> {
        return try {
            val accessibilityManager = context.getSystemService(Context.ACCESSIBILITY_SERVICE) 
                as? AccessibilityManager
            
            accessibilityManager?.getEnabledAccessibilityServiceList(
                AccessibilityServiceInfo.FEEDBACK_ALL_MASK
            ) ?: emptyList()
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Failed to get accessibility services", e)
            emptyList()
        }
    }
    
    /**
     * Check for suspicious accessibility services
     * These are known malware or automation tools
     */
    fun detectSuspiciousAccessibilityServices(context: Context): List<String> {
        val suspiciousServices = mutableListOf<String>()
        
        try {
            val enabledServices = getEnabledAccessibilityServices(context)
            
            // Known malicious/suspicious packages
            val suspiciousPackages = setOf(
                "com.teamviewer",                    // Remote control
                "com.anydesk",                       // Remote control
                "com.realvnc",                       // Remote control
                "com.chrome.dev",                    // Suspicious Chrome variant
                "com.test.accessibility",            // Test packages
                "accessibility.service",             // Generic suspicious
                "com.android.development",           // Development tools
                "com.accessibility.floatingmenu"     // Overlay tools
            )
            
            enabledServices.forEach { service ->
                val packageName = service.resolveInfo?.serviceInfo?.packageName ?: ""
                
                // Check against known suspicious packages
                if (suspiciousPackages.any { packageName.contains(it, ignoreCase = true) }) {
                    suspiciousServices.add(packageName)
                    android.util.Log.w(TAG, "Suspicious accessibility service: $packageName")
                }
                
                // Check for services with dangerous capabilities
                if (hasDangerousCapabilities(service)) {
                    suspiciousServices.add(packageName)
                    android.util.Log.w(TAG, "Accessibility service with dangerous capabilities: $packageName")
                }
            }
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Suspicious service detection failed", e)
        }
        
        return suspiciousServices
    }
    
    /**
     * Check if accessibility service has dangerous capabilities
     */
    private fun hasDangerousCapabilities(service: AccessibilityServiceInfo): Boolean {
        val dangerousCapabilities = arrayOf(
            AccessibilityServiceInfo.CAPABILITY_CAN_REQUEST_TOUCH_EXPLORATION, // Can intercept touches
            AccessibilityServiceInfo.CAPABILITY_CAN_REQUEST_FILTER_KEY_EVENTS,  // Can intercept keys
            AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT     // Can read screen
        )
        
        return dangerousCapabilities.any { capability ->
            (service.capabilities and capability) != 0
        }
    }
    
    /**
     * Check for overlay attacks using accessibility services
     * Detects if accessibility service can perform clicks
     */
    fun detectOverlayCapability(context: Context): Boolean {
        return try {
            val enabledServices = getEnabledAccessibilityServices(context)
            
            enabledServices.any { service ->
                // Check if service can perform gestures (potential overlay attack)
                (service.capabilities and AccessibilityServiceInfo.CAPABILITY_CAN_PERFORM_GESTURES) != 0
            }
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Overlay capability check failed", e)
            false
        }
    }
    
    /**
     * Check if any third-party (non-system) accessibility services are enabled
     */
    fun hasThirdPartyAccessibilityServices(context: Context): Boolean {
        return try {
            val enabledServices = getEnabledAccessibilityServices(context)
            
            // System packages that are safe
            val systemPackages = setOf(
                "com.android",
                "com.google.android",
                "android"
            )
            
            enabledServices.any { service ->
                val packageName = service.resolveInfo?.serviceInfo?.packageName ?: ""
                systemPackages.none { packageName.startsWith(it) }
            }
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Third-party check failed", e)
            false
        }
    }
    
    /**
     * Comprehensive accessibility threat detection
     */
    fun performAccessibilityCheck(context: Context): AccessibilityThreatResult {
        val accessibilityEnabled = isAccessibilityServiceEnabled(context)
        val suspiciousServices = detectSuspiciousAccessibilityServices(context)
        val overlayCapable = detectOverlayCapability(context)
        val hasThirdParty = hasThirdPartyAccessibilityServices(context)
        
        val threatLevel = when {
            suspiciousServices.isNotEmpty() -> ThreatLevel.CRITICAL
            overlayCapable && hasThirdParty -> ThreatLevel.HIGH
            hasThirdParty -> ThreatLevel.MEDIUM
            accessibilityEnabled -> ThreatLevel.LOW
            else -> ThreatLevel.NONE
        }
        
        return AccessibilityThreatResult(
            accessibilityEnabled = accessibilityEnabled,
            suspiciousServices = suspiciousServices,
            overlayCapabilityDetected = overlayCapable,
            hasThirdPartyServices = hasThirdParty,
            threatLevel = threatLevel,
            threatDetected = threatLevel != ThreatLevel.NONE
        )
    }
}

/**
 * Threat level enum
 */
enum class ThreatLevel {
    NONE,     // No threat
    LOW,      // Accessibility enabled but no suspicious services
    MEDIUM,   // Third-party accessibility service enabled
    HIGH,     // Dangerous capabilities detected
    CRITICAL  // Known malicious service detected
}

/**
 * Result of accessibility threat check
 */
data class AccessibilityThreatResult(
    val accessibilityEnabled: Boolean,
    val suspiciousServices: List<String>,
    val overlayCapabilityDetected: Boolean,
    val hasThirdPartyServices: Boolean,
    val threatLevel: ThreatLevel,
    val threatDetected: Boolean
) {
    fun getThreatDescription(): String {
        return when (threatLevel) {
            ThreatLevel.CRITICAL -> "Critical: Malicious accessibility service detected (${suspiciousServices.joinToString()})"
            ThreatLevel.HIGH -> "High: Accessibility service with dangerous capabilities detected"
            ThreatLevel.MEDIUM -> "Medium: Third-party accessibility service enabled"
            ThreatLevel.LOW -> "Low: Accessibility services are enabled"
            ThreatLevel.NONE -> "No accessibility threats detected"
        }
    }
}
