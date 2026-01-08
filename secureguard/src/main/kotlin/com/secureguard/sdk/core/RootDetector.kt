package com.secureguard.sdk.core

import android.content.Context
import android.os.Build
import com.secureguard.sdk.util.FileUtils
import com.secureguard.sdk.util.StringObfuscator
import java.io.File

/**
 * Root detection implementation
 * Detects if the device is rooted using multiple techniques
 */
object RootDetector {
    
    // Use obfuscated strings to prevent static analysis
    private val SU_PATHS get() = StringObfuscator.getAllSuPaths()
    
    private val DANGEROUS_PROPS = mapOf(
        "[ro.debuggable]" to "[1]",
        "[ro.secure]" to "[0]"
    )
    
    private val ROOT_APPS get() = StringObfuscator.getAllRootApps()
    
    /**
     * Check if device is rooted
     * EXPERT-PROOF: Native check runs autonomously, we just trigger it
     */
    fun isDeviceRooted(context: Context): Boolean {
        android.util.Log.e("RootDetector", "===== STARTING ROOT CHECK =====")
        
        // Trigger native autonomous enforcement (no return value needed)
        try {
            NativeSecurityBridge.checkRootNative()
        } catch (e: Exception) {
            // Native check failed, but enforcement still active
            android.util.Log.d("RootDetector", "Native root check exception: ${e.message}")
        }
        
        // Kotlin-level checks for scoring only
        val suBinary = checkSuBinary()
        val rootApps = checkRootManagementApps(context)
        val dangerousProps = checkDangerousProperties()
        val rwPaths = checkForRWPaths()
        
        android.util.Log.e("RootDetector", "Root check results:")
        android.util.Log.e("RootDetector", "  SU Binary: $suBinary")
        android.util.Log.e("RootDetector", "  Root Apps: $rootApps")
        android.util.Log.e("RootDetector", "  Dangerous Props: $dangerousProps")
        android.util.Log.e("RootDetector", "  RW Paths: $rwPaths")
        
        val isRooted = suBinary || rootApps || dangerousProps || rwPaths
        android.util.Log.e("RootDetector", "FINAL RESULT: isRooted = $isRooted")
        
        return isRooted
    }
    
    /**
     * Check for SU binary in common locations
     */
    private fun checkSuBinary(): Boolean {
        val foundPaths = SU_PATHS.filter { path ->
            try {
                val file = File(path)
                val exists = file.exists()
                val canExec = if (exists) file.canExecute() else false
                
                if (exists && canExec) {
                    android.util.Log.w("RootDetector", "SU binary found at: $path")
                }
                
                exists && canExec
            } catch (e: Exception) {
                android.util.Log.d("RootDetector", "Exception checking SU path $path: ${e.message}")
                false
            }
        }
        
        if (foundPaths.isNotEmpty()) {
            android.util.Log.w("RootDetector", "Found ${foundPaths.size} SU binaries: $foundPaths")
        } else {
            android.util.Log.d("RootDetector", "No SU binaries found")
        }
        
        return foundPaths.isNotEmpty()
    }
    
    /**
     * Check for root management apps
     */
    private fun checkRootManagementApps(context: Context): Boolean {
        val packageManager = context.packageManager
        return ROOT_APPS.any { packageName ->
            try {
                packageManager.getPackageInfo(packageName, 0)
                true
            } catch (e: Exception) {
                false
            }
        }
    }
    
    /**
     * Check for dangerous system properties
     */
    private fun checkDangerousProperties(): Boolean {
        val reader = ProcessBuilder()
            .command("getprop")
            .redirectErrorStream(true)
            .start()
        
        try {
            val output = reader.inputStream.bufferedReader().use { it.readText() }
            return DANGEROUS_PROPS.any { (key, value) ->
                output.contains("$key: $value", ignoreCase = true)
            }
        } catch (e: Exception) {
            return false
        } finally {
            reader.destroy()
        }
    }
    
    /**
     * Check for paths that should not be writable
     * Fixed to avoid false positives
     */
    private fun checkForRWPaths(): Boolean {
        val paths = arrayOf("/system", "/system/bin", "/system/sbin", "/system/xbin", "/vendor/bin", "/sbin", "/etc")
        
        val writablePaths = paths.filter { path ->
            try {
                val dir = File(path)
                if (!dir.exists() || !dir.isDirectory) {
                    return@filter false
                }
                
                // Check if directory is writable using canWrite()
                // Don't actually try to create files (causes false positives)
                val isWritable = dir.canWrite()
                
                if (isWritable) {
                    android.util.Log.w("RootDetector", "System path is writable: $path")
                }
                
                isWritable
            } catch (e: Exception) {
                android.util.Log.d("RootDetector", "Exception checking path $path: ${e.message}")
                false
            }
        }
        
        if (writablePaths.isNotEmpty()) {
            android.util.Log.w("RootDetector", "Found ${writablePaths.size} writable system paths: $writablePaths")
        }
        
        return writablePaths.isNotEmpty()
    }
    
    /**
     * Get detailed root information
     * EXPERT-PROOF: Native check triggers autonomous enforcement
     */
    fun getRootDetails(context: Context): Map<String, Boolean> {
        // Trigger native check (autonomous enforcement)
        try {
            NativeSecurityBridge.checkRootNative()
        } catch (e: Exception) {
            // Enforcement still active
        }
        
        return mapOf(
            "suBinary" to checkSuBinary(),
            "rootApps" to checkRootManagementApps(context),
            "dangerousProps" to checkDangerousProperties(),
            "rwPaths" to checkForRWPaths(),
            "nativeCheckActive" to true  // Always true - autonomous enforcement
        )
    }
    
    /**
     * Get all root indicators (flag-less check)
     * Returns list of detected root methods
     * EXPERT-PROOF: Native check triggers autonomous enforcement
     */
    fun getAllRootIndicators(context: Context): List<String> {
        android.util.Log.e("RootDetector", "===== getAllRootIndicators() CALLED =====")
        val indicators = mutableListOf<String>()
        
        val suResult = checkSuBinary()
        android.util.Log.e("RootDetector", "checkSuBinary() = $suResult")
        if (suResult) indicators.add("SU binary found")
        
        val rootAppsResult = checkRootManagementApps(context)
        android.util.Log.e("RootDetector", "checkRootManagementApps() = $rootAppsResult")
        if (rootAppsResult) indicators.add("Root management app installed")
        
        val dangerousPropsResult = checkDangerousProperties()
        android.util.Log.e("RootDetector", "checkDangerousProperties() = $dangerousPropsResult")
        if (dangerousPropsResult) indicators.add("Dangerous system properties")
        
        val rwPathsResult = checkForRWPaths()
        android.util.Log.e("RootDetector", "checkForRWPaths() = $rwPathsResult")
        if (rwPathsResult) indicators.add("System paths writable")
        
        // Trigger native check (autonomous enforcement)
        // Note: Native check doesn't return detection status, only triggers enforcement
        // So we DON'T add it as an indicator
        try {
            NativeSecurityBridge.checkRootNative()
            android.util.Log.e("RootDetector", "Native check triggered (no detection status returned)")
        } catch (e: Exception) {
            // Enforcement still active
            android.util.Log.e("RootDetector", "Native check exception: ${e.message}")
        }
        
        android.util.Log.e("RootDetector", "Total indicators found: ${indicators.size}")
        android.util.Log.e("RootDetector", "Indicators: $indicators")
        
        return indicators
    }
}
