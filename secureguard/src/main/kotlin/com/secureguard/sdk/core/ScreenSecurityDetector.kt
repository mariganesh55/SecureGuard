package com.secureguard.sdk.core

import android.content.Context
import android.hardware.display.DisplayManager
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.view.Display
import java.io.File

/**
 * Screen Recording & Screenshot Detection
 * Critical for banking apps to prevent:
 * - Screen recording malware
 * - Screenshot-based data theft
 * - Screen mirroring attacks
 */
object ScreenSecurityDetector {
    
    private const val TAG = "ScreenSecurity"
    
    /**
     * Check if screen is being recorded
     * Detects screen recording apps and screen mirroring
     */
    fun isScreenBeingRecorded(context: Context): Boolean {
        return checkMediaProjection(context) ||
               checkScreenRecordingApps(context) ||
               checkScreenMirroring(context)
    }
    
    /**
     * Check if MediaProjection API is active (screen recording)
     */
    private fun checkMediaProjection(context: Context): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                val mediaProjectionManager = context.getSystemService(Context.MEDIA_PROJECTION_SERVICE) 
                    as? MediaProjectionManager
                
                // Note: Can't directly check if recording is active
                // This is a limitation - we can only detect some indicators
                false // Placeholder - actual detection requires runtime checks
            } else {
                false
            }
        } catch (e: Exception) {
            android.util.Log.e(TAG, "MediaProjection check failed", e)
            false
        }
    }
    
    /**
     * Check for known screen recording apps
     */
    private fun checkScreenRecordingApps(context: Context): Boolean {
        val screenRecordingApps = arrayOf(
            "com.hecorat.screenrecorder.free",
            "com.kimcy929.screenrecorder",
            "com.nll.screenrecorder",
            "com.rivulus.screenrecording",
            "com.spectrl.nscreenrecorder",
            "com.mobizen.mirroring",
            "com.mobizen.screenmirror",
            "com.screen.recorder",
            "com.duapps.recorder",
            "com.capture.screenshot"
        )
        
        return screenRecordingApps.any { packageName ->
            isPackageInstalled(context, packageName)
        }
    }
    
    /**
     * Check if screen is being mirrored to external display
     */
    private fun checkScreenMirroring(context: Context): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                val displayManager = context.getSystemService(Context.DISPLAY_SERVICE) as? DisplayManager
                val displays = displayManager?.displays
                
                // Check for presentation displays (screen mirroring/casting)
                val hasMirroredDisplay = displays?.any { display ->
                    display.displayId != Display.DEFAULT_DISPLAY && 
                    display.state == Display.STATE_ON
                } ?: false
                
                if (hasMirroredDisplay) {
                    android.util.Log.w(TAG, "Screen mirroring detected")
                }
                
                hasMirroredDisplay
            } else {
                false
            }
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Screen mirroring check failed", e)
            false
        }
    }
    
    /**
     * Check if screen recording processes are running
     * Looks for screenrecord binary execution
     */
    fun checkScreenRecordProcess(): Boolean {
        return try {
            // Check for screenrecord process
            val process = Runtime.getRuntime().exec(arrayOf("sh", "-c", "ps | grep screenrecord"))
            val output = process.inputStream.bufferedReader().readText()
            
            val isRecording = output.contains("screenrecord") && !output.contains("grep")
            
            if (isRecording) {
                android.util.Log.w(TAG, "screenrecord process detected")
            }
            
            isRecording
        } catch (e: Exception) {
            // Permission denied or process check failed
            false
        }
    }
    
    /**
     * Check for screenshot capture attempts
     * Detects screenshot files being created
     */
    fun detectRecentScreenshots(): Boolean {
        return try {
            val screenshotPaths = arrayOf(
                "/sdcard/Pictures/Screenshots",
                "/sdcard/DCIM/Screenshots",
                "/sdcard/Screenshots"
            )
            
            val now = System.currentTimeMillis()
            val fiveSecondsAgo = now - 5000 // 5 seconds
            
            screenshotPaths.any { path ->
                val dir = File(path)
                if (dir.exists() && dir.isDirectory) {
                    dir.listFiles()?.any { file ->
                        file.lastModified() > fiveSecondsAgo
                    } ?: false
                } else {
                    false
                }
            }
        } catch (e: Exception) {
            // Storage permission denied or path doesn't exist
            false
        }
    }
    
    /**
     * Comprehensive screen security check
     */
    fun performScreenSecurityCheck(context: Context): ScreenSecurityResult {
        val screenRecording = isScreenBeingRecorded(context)
        val recordingProcess = checkScreenRecordProcess()
        val recentScreenshot = detectRecentScreenshots()
        
        val threat = screenRecording || recordingProcess || recentScreenshot
        
        return ScreenSecurityResult(
            screenRecordingActive = screenRecording,
            recordingProcessRunning = recordingProcess,
            recentScreenshotDetected = recentScreenshot,
            threatDetected = threat
        )
    }
    
    /**
     * Check if package is installed
     */
    private fun isPackageInstalled(context: Context, packageName: String): Boolean {
        return try {
            context.packageManager.getPackageInfo(packageName, 0)
            true
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Get screen threat level (0-100) - flag-less check
     * Higher score = more screen-related threats
     */
    fun getScreenThreatLevel(context: Context): Int {
        var score = 0
        
        if (isScreenBeingRecorded(context)) score += 40
        if (checkScreenRecordProcess()) score += 30
        if (detectRecentScreenshots()) score += 20
        // Screen mirroring detection requires additional permissions
        
        return score.coerceIn(0, 100)
    }
}

/**
 * Result of screen security check
 */
data class ScreenSecurityResult(
    val screenRecordingActive: Boolean,
    val recordingProcessRunning: Boolean,
    val recentScreenshotDetected: Boolean,
    val threatDetected: Boolean
) {
    fun getThreatDescriptions(): List<String> {
        val threats = mutableListOf<String>()
        if (screenRecordingActive) threats.add("Screen recording app detected")
        if (recordingProcessRunning) threats.add("Screen record process running")
        if (recentScreenshotDetected) threats.add("Recent screenshot detected")
        return threats
    }
}
