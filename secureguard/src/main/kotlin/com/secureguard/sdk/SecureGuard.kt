package com.secureguard.sdk

import android.app.Application
import android.content.Context
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleObserver
import androidx.lifecycle.OnLifecycleEvent
import androidx.lifecycle.ProcessLifecycleOwner
import com.secureguard.sdk.core.*
import kotlinx.coroutines.*

/**
 * Main entry point for SecureGuard SDK
 * Provides comprehensive security monitoring for Android apps
 * 
 * NEW: Flag-less security architecture
 * - No boolean flags that can be bypassed
 * - Score-based threat detection (0-100)
 * - Multi-layer redundant checks
 * - Evidence-based decision making
 */
class SecureGuard private constructor(
    private val context: Context,
    private val config: SecurityConfig,
    private val callback: SecurityCallback?
) : LifecycleObserver {
    
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var isInitialized = false
    private var monitoringJob: Job? = null
    
    companion object {
        @Volatile
        private var INSTANCE: SecureGuard? = null
        
        private const val TAG = "SecureGuard"
        
        /**
         * Initialize SecureGuard SDK
         * Must be called before using any security features
         */
        fun initialize(
            application: Application,
            config: SecurityConfig,
            callback: SecurityCallback? = null
        ): SecureGuard {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: SecureGuard(
                    application.applicationContext,
                    config,
                    callback
                ).also { 
                    INSTANCE = it
                    it.start()
                }
            }
        }
        
        /**
         * Get initialized instance
         */
        fun getInstance(): SecureGuard? = INSTANCE
    }
    
    /**
     * Start security monitoring
     */
    private fun start() {
        if (isInitialized) {
            android.util.Log.w(TAG, "SecureGuard already initialized")
            return
        }
        
        // Initialize native library
        NativeSecurityBridge.initialize()
        
        // Register lifecycle observer if app resume checks are enabled
        if (config.checkOnAppResume) {
            ProcessLifecycleOwner.get().lifecycle.addObserver(this)
        }
        
        // Start initial security checks
        // Use comprehensive scan (flag-less) for maximum security
        scope.launch {
            performComprehensiveScan()
        }
        
        // Start continuous monitoring if enabled
        if (config.enableContinuousMonitoring && config.monitoringIntervalSeconds > 0) {
            startContinuousMonitoring()
        }
        
        isInitialized = true
        android.util.Log.i(TAG, "SecureGuard initialized successfully")
    }
    
    /**
     * Start continuous security monitoring
     */
    private fun startContinuousMonitoring() {
        monitoringJob?.cancel()
        monitoringJob = scope.launch {
            while (isActive) {
                delay(config.monitoringIntervalSeconds * 1000)
                // Use comprehensive scan (flag-less)
                performComprehensiveScan()
            }
        }
        android.util.Log.i(TAG, "Continuous monitoring started (interval: ${config.monitoringIntervalSeconds}s)")
    }
    
    /**
     * Stop continuous monitoring
     */
    private fun stopContinuousMonitoring() {
        monitoringJob?.cancel()
        monitoringJob = null
        android.util.Log.i(TAG, "Continuous monitoring stopped")
    }
    
    /**
     * Called when app comes to foreground
     */
    @OnLifecycleEvent(Lifecycle.Event.ON_RESUME)
    fun onAppResumed() {
        android.util.Log.d(TAG, "App resumed - performing security check")
        scope.launch {
            // Use comprehensive scan (no flags!)
            performComprehensiveScan()
        }
    }
    
    /**
     * Perform comprehensive security scan (FLAG-LESS)
     * Uses AntiTamperEngine for multi-layer detection
     * NO boolean flags - ALWAYS checks everything
     */
    private suspend fun performComprehensiveScan() {
        withContext(Dispatchers.Default) {
            try {
                // Run comprehensive scan (no flags to bypass!)
                val result = AntiTamperEngine.performComprehensiveScan(context)
                
                android.util.Log.i(TAG, "Security scan complete:")
                android.util.Log.i(TAG, "  Threat Score: ${result.threatScore}/100")
                android.util.Log.i(TAG, "  Checks Passed: ${result.checksPassed}")
                android.util.Log.i(TAG, "  Checks Warning: ${result.checksWarning}")
                android.util.Log.i(TAG, "  Checks Failed: ${result.checksFailed}")
                android.util.Log.i(TAG, "  Threats: ${result.threats.joinToString()}")
                
                // Notify about detected threats
                result.threats.forEach { threatType ->
                    val description = getThreatDescription(threatType, result)
                    callback?.onThreatDetected(threatType, description)
                }
                
                // Security check complete callback
                val passed = result.threatScore < 25  // Calculated, not a flag!
                callback?.onSecurityCheckComplete(passed, result.threats)
                
                // Handle critical threats (score > 70)
                if (config.blockOnThreat && result.isDangerous) {
                    android.util.Log.e(TAG, "CRITICAL THREAT DETECTED - Threat Score: ${result.threatScore}")
                    android.util.Log.e(TAG, "Application security compromised. Exiting...")
                    // Let callback handle the exit
                    callback?.onThreatDetected(ThreatType.TAMPERING_DETECTED, 
                        "Critical security threat detected (Score: ${result.threatScore})")
                }
                
                Unit  // Explicit return type to avoid if expression issue
                
            } catch (e: Exception) {
                android.util.Log.e(TAG, "Security scan failed", e)
            }
        }
    }
    
    /**
     * Perform all security checks (LEGACY - Still supported)
     * Note: This method still uses config flags for backward compatibility
     * For maximum security, use performComprehensiveScan() instead
     */
    private suspend fun performSecurityChecks() {
        withContext(Dispatchers.Default) {
            val threats = mutableListOf<ThreatType>()
        
        // Root Detection
        if (config.enableRootDetection) {
            launch {
                if (RootDetector.isDeviceRooted(context)) {
                    threats.add(ThreatType.ROOT_DETECTED)
                    callback?.onThreatDetected(ThreatType.ROOT_DETECTED, "Device is rooted")
                }
            }
        }
        
        // Emulator Detection
        if (config.enableEmulatorDetection) {
            launch {
                if (EmulatorDetector.isEmulator(context)) {
                    threats.add(ThreatType.EMULATOR_DETECTED)
                    callback?.onThreatDetected(ThreatType.EMULATOR_DETECTED, "Running on emulator")
                }
            }
        }
        
        // Debugger Detection
        if (config.enableDebuggerDetection) {
            launch {
                if (DebuggerDetector.isDebuggerAttached(context)) {
                    threats.add(ThreatType.DEBUGGER_DETECTED)
                    callback?.onThreatDetected(ThreatType.DEBUGGER_DETECTED, "Debugger attached")
                }
            }
        }
        
        // Hooking Framework Detection
        if (config.enableHookingDetection) {
            launch {
                val hookingFramework = HookingDetector.detectHookingFramework(context)
                if (hookingFramework != null) {
                    threats.add(ThreatType.HOOKING_DETECTED)
                    callback?.onThreatDetected(
                        ThreatType.HOOKING_DETECTED,
                        "Hooking framework detected: $hookingFramework"
                    )
                }
            }
        }
        
        // APK Integrity Checks
        if (config.enableIntegrityChecks) {
            launch {
                val result = IntegrityChecker.performIntegrityCheck(context, config.expectedSignatureHash)
                if (!result.passed) {
                    result.getFailureReasons().forEach { reason ->
                        val threatType = when {
                            !result.signatureValid -> ThreatType.INVALID_SIGNATURE
                            !result.installerValid -> ThreatType.INVALID_INSTALLER
                            !result.apkNotModified -> ThreatType.APK_MODIFIED
                            else -> ThreatType.TAMPERING_DETECTED
                        }
                        threats.add(threatType)
                        callback?.onThreatDetected(threatType, reason)
                    }
                }
            }
        }
        
        // Screen Security Checks
        if (config.enableScreenSecurityChecks) {
            launch {
                val result = ScreenSecurityDetector.performScreenSecurityCheck(context)
                if (result.threatDetected) {
                    result.getThreatDescriptions().forEach { description ->
                        val threatType = when {
                            result.screenRecordingActive -> ThreatType.SCREEN_RECORDING_DETECTED
                            result.recentScreenshotDetected -> ThreatType.SCREENSHOT_DETECTED
                            else -> ThreatType.SCREEN_RECORDING_DETECTED
                        }
                        threats.add(threatType)
                        callback?.onThreatDetected(threatType, description)
                    }
                }
            }
        }
        
        // Accessibility Service Checks
        if (config.enableAccessibilityChecks) {
            launch {
                val result = AccessibilityDetector.performAccessibilityCheck(context)
                if (result.threatDetected) {
                    threats.add(ThreatType.ACCESSIBILITY_THREAT)
                    callback?.onThreatDetected(
                        ThreatType.ACCESSIBILITY_THREAT,
                        result.getThreatDescription()
                    )
                }
            }
        }
        
        // Debugger Detection
        if (config.enableDebuggerDetection) {
            launch {
                if (DebuggerDetector.isDebuggerAttached(context)) {
                    threats.add(ThreatType.DEBUGGER_DETECTED)
                    callback?.onThreatDetected(ThreatType.DEBUGGER_DETECTED, "Debugger attached")
                }
            }
        }
        
        // Hooking Framework Detection
        if (config.enableHookingDetection) {
            launch {
                val hookingFramework = HookingDetector.detectHookingFramework(context)
                if (hookingFramework != null) {
                    threats.add(ThreatType.HOOKING_DETECTED)
                    callback?.onThreatDetected(
                        ThreatType.HOOKING_DETECTED,
                        "Hooking framework detected: $hookingFramework"
                    )
                }
            }
        }
        
        // Wait for all checks to complete
        delay(500)
        
        // Notify completion
        if (threats.isEmpty()) {
            callback?.onSecurityCheckComplete(true, emptyList())
        } else {
            callback?.onSecurityCheckComplete(false, threats)
        }
        }
    }
    
    /**
     * Manually trigger security scan (FLAG-LESS - Comprehensive)
     */
    fun scan() {
        scope.launch {
            performComprehensiveScan()
        }
    }
    
    /**
     * Manually trigger legacy security scan (uses config flags)
     */
    fun scanLegacy() {
        scope.launch {
            performSecurityChecks()
        }
    }
    
    /**
     * Get threat description from scan result
     */
    private fun getThreatDescription(threatType: ThreatType, result: SecurityScanResult): String {
        return when (threatType) {
            ThreatType.ROOT_DETECTED -> "Device is rooted (Score: ${result.threatScore})"
            ThreatType.EMULATOR_DETECTED -> "Running on emulator (Score: ${result.threatScore})"
            ThreatType.DEBUGGER_DETECTED -> "Debugger attached (Score: ${result.threatScore})"
            ThreatType.HOOKING_DETECTED -> "Hooking framework detected (Score: ${result.threatScore})"
            ThreatType.TAMPERING_DETECTED -> "App tampering detected (Score: ${result.threatScore})"
            ThreatType.INVALID_SIGNATURE -> "Invalid APK signature (Score: ${result.threatScore})"
            ThreatType.INVALID_INSTALLER -> "Invalid installer source (Score: ${result.threatScore})"
            ThreatType.APK_MODIFIED -> "APK file modified (Score: ${result.threatScore})"
            ThreatType.SCREEN_RECORDING_DETECTED -> "Screen recording active (Score: ${result.threatScore})"
            ThreatType.SCREENSHOT_DETECTED -> "Screenshot detected (Score: ${result.threatScore})"
            ThreatType.SCREEN_MIRRORING_DETECTED -> "Screen mirroring active (Score: ${result.threatScore})"
            ThreatType.ACCESSIBILITY_THREAT -> "Accessibility threat detected (Score: ${result.threatScore})"
            ThreatType.OVERLAY_ATTACK -> "Overlay attack detected (Score: ${result.threatScore})"
            ThreatType.SSL_PINNING_FAILED -> "SSL pinning failed (Score: ${result.threatScore})"
            else -> "Unknown threat (Score: ${result.threatScore})"
        }
    }
    
    /**
     * Check if device is rooted (Legacy API)
     */
    fun isRooted(): Boolean = RootDetector.isDeviceRooted(context)
    
    /**
     * Check if running on emulator (Legacy API)
     */
    fun isEmulator(): Boolean = EmulatorDetector.isEmulator(context)
    
    /**
     * Check if debugger is attached (Legacy API)
     */
    fun isDebugging(): Boolean = DebuggerDetector.isDebuggerAttached(context)
    
    /**
     * Detect hooking frameworks (Legacy API)
     */
    fun detectHooking(): String? = HookingDetector.detectHookingFramework(context)
    
    /**
     * Clean up resources
     */
    fun destroy() {
        stopContinuousMonitoring()
        scope.cancel()
        if (config.checkOnAppResume) {
            ProcessLifecycleOwner.get().lifecycle.removeObserver(this)
        }
        INSTANCE = null
        isInitialized = false
        android.util.Log.i(TAG, "SecureGuard destroyed")
    }
}
