package com.secureguard.sdk.core

import android.content.Context
import com.secureguard.sdk.util.StringObfuscator
import java.io.File

/**
 * Hooking framework detection (Frida, Xposed, LSPosed, etc.)
 * Detects if the app is being hooked or instrumented
 */
object HookingDetector {
    
    // Use obfuscated strings to hide detection logic
    private val FRIDA_LIBS get() = StringObfuscator.getAllFridaLibs()
    private val XPOSED_PACKAGES get() = StringObfuscator.getAllXposedPackages()
    private val LSPOSED_PACKAGES get() = StringObfuscator.getAllLSPosedPackages()
    private val FRIDA_FILES get() = StringObfuscator.getAllFridaFiles()
    
    /**
     * Detect hooking frameworks
     * Returns the detected framework name or null
     */
    fun detectHookingFramework(context: Context): String? {
        return when {
            detectFrida(context) -> "Frida"
            detectXposed(context) -> "Xposed"
            detectLSPosed(context) -> "LSPosed"
            detectSubstrate() -> "Cydia Substrate"
            else -> null
        }
    }
    
    /**
     * Detect Frida
     * EXPERT-PROOF: Native check runs autonomously, we just trigger it
     */
    private fun detectFrida(context: Context): Boolean {
        // Trigger native autonomous enforcement (no return value needed)
        try {
            NativeSecurityBridge.checkFridaNative()
        } catch (e: Exception) {
            // Native check failed, but enforcement still active
        }
        
        // Kotlin-level checks for scoring only
        return checkFridaFiles() ||
               checkFridaPort() ||
               checkFridaInMaps()
    }
    
    /**
     * Check for Frida files
     */
    private fun checkFridaFiles(): Boolean {
        return FRIDA_FILES.any { path ->
            File(path).exists()
        }
    }
    
    /**
     * Check for Frida default port (27042)
     */
    private fun checkFridaPort(): Boolean {
        return try {
            val tcpFile = File(StringObfuscator.sysPath3()) // /proc/net/tcp
            if (tcpFile.exists()) {
                val content = tcpFile.readText()
                // Use obfuscated port hex value
                content.contains(StringObfuscator.fridaPortHex(), ignoreCase = true)
            } else {
                false
            }
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Check for Frida libraries in memory maps
     */
    private fun checkFridaInMaps(): Boolean {
        return try {
            val mapsFile = File("/proc/self/maps")
            if (mapsFile.exists()) {
                val content = mapsFile.readText()
                FRIDA_LIBS.any { lib ->
                    content.contains(lib, ignoreCase = true)
                }
            } else {
                false
            }
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Detect Xposed framework
     */
    private fun detectXposed(context: Context): Boolean {
        return checkXposedInstalled(context) ||
               checkXposedStack() ||
               checkXposedBridge()
    }
    
    /**
     * Check if Xposed packages are installed
     */
    private fun checkXposedInstalled(context: Context): Boolean {
        val packageManager = context.packageManager
        return XPOSED_PACKAGES.any { packageName ->
            try {
                packageManager.getPackageInfo(packageName, 0)
                true
            } catch (e: Exception) {
                false
            }
        }
    }
    
    /**
     * Check for Xposed in stack trace
     */
    private fun checkXposedStack(): Boolean {
        return try {
            throw Exception("Stack trace check")
        } catch (e: Exception) {
            e.stackTrace.any { element ->
                element.className.contains("de.robv.android.xposed", ignoreCase = true) ||
                element.className.contains("com.saurik.substrate", ignoreCase = true)
            }
        }
    }
    
    /**
     * Check for XposedBridge class
     */
    private fun checkXposedBridge(): Boolean {
        return try {
            Class.forName(StringObfuscator.xposedBridgeClass())
            true
        } catch (e: ClassNotFoundException) {
            false
        }
    }
    
    /**
     * Detect LSPosed
     */
    private fun detectLSPosed(context: Context): Boolean {
        val packageManager = context.packageManager
        return LSPOSED_PACKAGES.any { packageName ->
            try {
                packageManager.getPackageInfo(packageName, 0)
                true
            } catch (e: Exception) {
                false
            }
        }
    }
    
    /**
     * Detect Cydia Substrate
     */
    private fun detectSubstrate(): Boolean {
        return try {
            Class.forName("com.saurik.substrate.MS$2")
            true
        } catch (e: ClassNotFoundException) {
            false
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Get detailed hooking detection information
     */
    fun getHookingDetails(context: Context): Map<String, Boolean> {
        return mapOf(
            "frida" to detectFrida(context),
            "xposed" to detectXposed(context),
            "lsposed" to detectLSPosed(context),
            "substrate" to detectSubstrate()
        )
    }
    
    /**
     * Get all hooking indicators (flag-less check)
     * Returns list of detected hooking frameworks
     */
    fun getAllHookingIndicators(context: Context): List<String> {
        android.util.Log.e("HookingDetector", "===== getAllHookingIndicators() CALLED =====")
        val indicators = mutableListOf<String>()
        
        val fridaResult = detectFrida(context)
        android.util.Log.e("HookingDetector", "detectFrida() = $fridaResult")
        if (fridaResult) indicators.add("Frida framework detected")
        
        val xposedResult = detectXposed(context)
        android.util.Log.e("HookingDetector", "detectXposed() = $xposedResult")
        if (xposedResult) indicators.add("Xposed framework detected")
        
        val lsposedResult = detectLSPosed(context)
        android.util.Log.e("HookingDetector", "detectLSPosed() = $lsposedResult")
        if (lsposedResult) indicators.add("LSPosed framework detected")
        
        val substrateResult = detectSubstrate()
        android.util.Log.e("HookingDetector", "detectSubstrate() = $substrateResult")
        if (substrateResult) indicators.add("Cydia Substrate detected")
        
        android.util.Log.e("HookingDetector", "Total indicators: ${indicators.size}")
        android.util.Log.e("HookingDetector", "Indicators: $indicators")
        
        return indicators
    }
}
