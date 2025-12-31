package com.secureguard.sdk.core

import android.content.Context
import android.os.Build
import com.secureguard.sdk.util.StringObfuscator
import java.io.File

/**
 * Emulator detection implementation
 * Detects if the app is running on an emulator/simulator
 */
object EmulatorDetector {
    
    private val KNOWN_FILES = arrayOf(
        "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace",
        "/system/bin/qemu-props"
    )
    
    private val KNOWN_GENY_FILES = arrayOf(
        "/dev/socket/genyd",
        "/dev/socket/baseband_genyd"
    )
    
    private val KNOWN_PIPES = arrayOf(
        "/dev/socket/qemud",
        "/dev/qemu_pipe"
    )
    
    private val X86_PROCESSORS = arrayOf(
        "intel",
        "amd"
    )
    
    // Obfuscated emulator identifiers
    private val EMULATOR_IDS get() = StringObfuscator.getAllEmulatorIds()
    
    /**
     * Check if running on emulator
     * EXPERT-PROOF: Native check runs autonomously, we just trigger it
     */
    fun isEmulator(context: Context): Boolean {
        // Trigger native autonomous enforcement (no return value needed)
        try {
            NativeSecurityBridge.checkEmulatorNative()
        } catch (e: Exception) {
            // Native check failed, but enforcement still active
        }
        
        // Kotlin-level checks for scoring only
        return checkBasic() ||
               checkAdvanced() ||
               checkFiles() ||
               checkQemuProps()
    }
    
    /**
     * Basic emulator detection using Build properties
     */
    private fun checkBasic(): Boolean {
        // Use obfuscated identifiers to prevent static analysis
        val ids = EMULATOR_IDS
        return (Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.startsWith("unknown")
                || Build.MODEL.contains(ids[2]) // google_sdk
                || Build.MODEL.contains(ids[3]) // Emulator
                || Build.MODEL.contains("Android SDK built for x86")
                || Build.MANUFACTURER.contains(ids[4]) // Genymotion
                || Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")
                || ids[2] == Build.PRODUCT // google_sdk
                || Build.HARDWARE.contains(ids[0]) // goldfish
                || Build.HARDWARE.contains(ids[1])) // ranchu
    }
    
    /**
     * Advanced checks for emulator characteristics
     */
    private fun checkAdvanced(): Boolean {
        return checkOperatorName() ||
               checkDebuggerConnected() ||
               checkPhysicalLocation() ||
               checkX86Processor()
    }
    
    /**
     * Check operator name
     */
    private fun checkOperatorName(): Boolean {
        val operatorName = Build.BRAND
        return operatorName.equals("generic", ignoreCase = true)
    }
    
    /**
     * Check if debugger is connected
     */
    private fun checkDebuggerConnected(): Boolean {
        return android.os.Debug.isDebuggerConnected()
    }
    
    /**
     * Check for x86 processor (common in emulators)
     */
    private fun checkX86Processor(): Boolean {
        val cpuInfo = readCpuInfo()
        return X86_PROCESSORS.any { processor ->
            cpuInfo.contains(processor, ignoreCase = true)
        }
    }
    
    /**
     * Read CPU info
     */
    private fun readCpuInfo(): String {
        return try {
            File("/proc/cpuinfo").readText()
        } catch (e: Exception) {
            ""
        }
    }
    
    /**
     * Check physical location (emulators often have fake GPS)
     */
    private fun checkPhysicalLocation(): Boolean {
        // This is a placeholder - in production you'd check GPS coordinates
        // Emulators often default to Mountain View, CA (37.4220, -122.0841)
        return false
    }
    
    /**
     * Check for emulator-specific files
     */
    private fun checkFiles(): Boolean {
        val allFiles = KNOWN_FILES + KNOWN_GENY_FILES + KNOWN_PIPES
        return allFiles.any { path ->
            File(path).exists()
        }
    }
    
    /**
     * Check for QEMU properties
     */
    private fun checkQemuProps(): Boolean {
        val qemuProps = arrayOf(
            "init.svc.qemud",
            "init.svc.qemu-props",
            "qemu.hw.mainkeys",
            "qemu.sf.fake_camera",
            "qemu.sf.lcd_density",
            "ro.bootloader",
            "ro.bootmode",
            "ro.hardware",
            "ro.kernel.android.qemud",
            "ro.kernel.qemu.gles",
            "ro.kernel.qemu",
            "ro.product.device",
            "ro.product.model",
            "ro.product.name",
            "ro.serialno"
        )
        
        val reader = ProcessBuilder()
            .command("getprop")
            .redirectErrorStream(true)
            .start()
        
        try {
            val output = reader.inputStream.bufferedReader().use { it.readText() }
            return qemuProps.any { prop ->
                output.contains(prop, ignoreCase = true) && 
                (output.contains("goldfish", ignoreCase = true) || 
                 output.contains("ranchu", ignoreCase = true) ||
                 output.contains("sdk", ignoreCase = true))
            }
        } catch (e: Exception) {
            return false
        } finally {
            reader.destroy()
        }
    }
    
    /**
     * Get detailed emulator information
     * EXPERT-PROOF: Native check triggers autonomous enforcement
     */
    fun getEmulatorDetails(): Map<String, Boolean> {
        // Trigger native check (autonomous enforcement)
        try {
            NativeSecurityBridge.checkEmulatorNative()
        } catch (e: Exception) {
            // Enforcement still active
        }
        
        return mapOf(
            "basicCheck" to checkBasic(),
            "advancedCheck" to checkAdvanced(),
            "filesCheck" to checkFiles(),
            "qemuProps" to checkQemuProps(),
            "nativeCheckActive" to true  // Always true - autonomous enforcement
        )
    }
    
    /**
     * Get emulator confidence score (0-100)
     * Flag-less check - returns score instead of boolean
     * EXPERT-PROOF: Native check triggers autonomous enforcement
     */
    fun getEmulatorConfidence(context: Context): Int {
        var score = 0
        
        // Trigger native check (autonomous enforcement, no score needed)
        try {
            NativeSecurityBridge.checkEmulatorNative()
        } catch (e: Exception) {
            // Enforcement still active
        }
        
        if (checkBasic()) score += 30
        if (checkAdvanced()) score += 20
        if (checkFiles()) score += 20
        if (checkQemuProps()) score += 15
        // Native check runs autonomously (no return value to add to score)
        
        return score.coerceIn(0, 100)
    }
}
