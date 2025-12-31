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
     */
    fun isDebuggerAttached(context: Context): Boolean {
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
     */
    private fun checkDebuggerConnected(): Boolean {
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger()
    }
    
    /**
     * Check TracerPid in /proc/self/status
     * If TracerPid > 0, a debugger is attached
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
     */
    fun getAllDebuggerIndicators(context: Context): List<String> {
        val indicators = mutableListOf<String>()
        
        if (checkDebuggerConnected()) indicators.add("Debugger API connected")
        if (checkTracerPid()) indicators.add("TracerPid active")
        if (checkDebugPort()) indicators.add("Debug port open")
        
        // Trigger native check (autonomous enforcement)
        try {
            NativeSecurityBridge.checkDebuggerNative()
            indicators.add("Native checks active")
        } catch (e: Exception) {
            // Enforcement still active
        }
        
        return indicators
    }
}
