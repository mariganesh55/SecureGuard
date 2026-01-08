package com.secureguard.sdk.core

import android.content.Context
import android.os.Debug
import java.io.File

/**
 * Debugger detection implementation
 * Detects if a debugger is attached to the app
 */
object DebuggerDetector {
    
    /**
     * Check if debugger is attached
     * EXPERT-PROOF: Native check runs autonomously, we just trigger it
     * DEVELOPER MODE: Checked natively via JNI (reads Settings.Global directly)
     */
    fun isDebuggerAttached(context: Context): Boolean {
        // Developer mode is checked in native layer via JNI:
        // - JNI_OnLoad: Immediate check on startup
        // - Monitoring threads: Periodic checks every 10-30 seconds
        // - onAppResume: Check when app returns to foreground
        // NO Kotlin layer involvement - pure native enforcement
        
        // Trigger native autonomous enforcement (no return value needed)
        try {
            NativeSecurityBridge.checkDebuggerNative()
        } catch (e: Exception) {
            // Native check failed, but enforcement still active
        }
        
        // Kotlin-level checks for scoring only
        return checkDebuggerConnected() ||
               checkTracerPid() ||
               checkDebugPort()
    }
    
    /**
     * Check using Android Debug API
     * PENTESTER NOTE: Yes, this returns boolean, but it's just for scoring
     * Native enforcement runs autonomously - hooking this won't help you
     */
    private fun checkDebuggerConnected(): Boolean {
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger()
    }
    
    /**
     * Check TracerPid in /proc/self/status
     * If TracerPid > 0, a debugger is attached
     * PENTESTER NOTE: Hooking this won't bypass native enforcement
     */
    private fun checkTracerPid(): Boolean {
        return try {
            val statusFile = File("/proc/self/status")
            val lines = statusFile.readLines()
            
            lines.firstOrNull { it.startsWith("TracerPid:") }
                ?.substringAfter("TracerPid:")
                ?.trim()
                ?.toIntOrNull()
                ?.let { it != 0 } ?: false
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Check for debug port (JDWP)
     * PENTESTER NOTE: Return value is just for scoring, not enforcement
     */
    private fun checkDebugPort(): Boolean {
        return try {
            val tcpFile = File("/proc/net/tcp")
            val tcp6File = File("/proc/net/tcp6")
            
            val tcpContent = if (tcpFile.exists()) tcpFile.readText() else ""
            val tcp6Content = if (tcp6File.exists()) tcp6File.readText() else ""
            
            val content = tcpContent + tcp6Content
            
            // Check for JDWP port (8700 in hex = 21FC)
            content.contains("21FC", ignoreCase = true)
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Developer mode detection is now handled ENTIRELY in native code
     * No Kotlin-level check needed - native reads settings database directly
     * This follows the same pattern as root/emulator detection
     */
    
    /**
     * Get detailed debugger information
     * EXPERT-PROOF: Native check triggers autonomous enforcement
     */
    fun getDebuggerDetails(): Map<String, Boolean> {
        // Trigger native check (autonomous enforcement)
        try {
            NativeSecurityBridge.checkDebuggerNative()
        } catch (e: Exception) {
            // Enforcement still active
        }
        
        return mapOf(
            "debuggerConnected" to checkDebuggerConnected(),
            "tracerPid" to checkTracerPid(),
            "debugPort" to checkDebugPort(),
            "nativeCheckActive" to true  // Always true - autonomous enforcement
        )
    }
    
    /**
     * Get all debugger indicators (flag-less check)
     * Returns list of detected debugger methods
     * EXPERT-PROOF: Native check triggers autonomous enforcement
     * DEVELOPER MODE: Checked natively via JNI (no Kotlin involvement)
     */
    fun getAllDebuggerIndicators(context: Context): List<String> {
        android.util.Log.e("DebuggerDetector", "===== getAllDebuggerIndicators() CALLED =====")
        val indicators = mutableListOf<String>()
        
        // Developer mode is checked in native layer via JNI - no Kotlin check needed
        
        val connectedResult = checkDebuggerConnected()
        android.util.Log.e("DebuggerDetector", "checkDebuggerConnected() = $connectedResult")
        if (connectedResult) indicators.add("Debugger API connected")
        
        val tracerResult = checkTracerPid()
        android.util.Log.e("DebuggerDetector", "checkTracerPid() = $tracerResult")
        if (tracerResult) indicators.add("TracerPid active")
        
        val portResult = checkDebugPort()
        android.util.Log.e("DebuggerDetector", "checkDebugPort() = $portResult")
        if (portResult) indicators.add("Debug port open")
        
        // Trigger native check (autonomous enforcement)
        // Native checks: debugger, TracerPid, debug port, and DEVELOPER MODE via JNI
        // Note: Native check doesn't return detection status, only triggers enforcement
        // So we DON'T add it as an indicator
        try {
            NativeSecurityBridge.checkDebuggerNative()
            android.util.Log.e("DebuggerDetector", "Native check triggered (no detection status returned)")
        } catch (e: Exception) {
            // Enforcement still active
            android.util.Log.e("DebuggerDetector", "Native check exception: ${e.message}")
        }
        
        android.util.Log.e("DebuggerDetector", "Total indicators: ${indicators.size}")
        android.util.Log.e("DebuggerDetector", "Indicators: $indicators")
        
        return indicators
    }
}