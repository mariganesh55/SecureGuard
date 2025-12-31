package com.secureguard.sdk.core

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.security.MessageDigest
import java.security.cert.Certificate

/**
 * APK Integrity Checker
 * Detects if the APK has been tampered with, repackaged, or modified
 * Critical for banking apps to prevent code injection attacks
 */
object IntegrityChecker {
    
    private const val TAG = "IntegrityChecker"
    
    /**
     * Verify APK signature hasn't been modified
     * Compares current signature with expected signature hash
     * 
     * @param context Application context
     * @param expectedSignatureHash SHA-256 hash of legitimate signature
     * @return true if signature is valid, false if tampered
     */
    fun verifySignature(context: Context, expectedSignatureHash: String? = null): Boolean {
        return try {
            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val packageInfo = context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
                packageInfo.signingInfo?.apkContentsSigners ?: emptyArray()
            } else {
                @Suppress("DEPRECATION")
                val packageInfo = context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNATURES
                )
                @Suppress("DEPRECATION")
                packageInfo.signatures ?: emptyArray()
            }
            
            if (signatures.isEmpty()) {
                android.util.Log.w(TAG, "No signatures found - APK may be tampered")
                return false
            }
            
            // If no expected hash provided, just verify signature exists
            if (expectedSignatureHash == null) {
                return true
            }
            
            // Verify signature matches expected hash
            val currentSignatureHash = getSignatureHash(signatures[0])
            val matches = currentSignatureHash.equals(expectedSignatureHash, ignoreCase = true)
            
            if (!matches) {
                android.util.Log.e(TAG, "Signature mismatch - APK has been repackaged!")
                android.util.Log.e(TAG, "Expected: $expectedSignatureHash")
                android.util.Log.e(TAG, "Current: $currentSignatureHash")
            }
            
            matches
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Signature verification failed", e)
            false
        }
    }
    
    /**
     * Get SHA-256 hash of APK signature
     * Use this during development to get your legitimate signature hash
     */
    fun getSignatureHash(context: Context): String? {
        return try {
            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val packageInfo = context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
                packageInfo.signingInfo?.apkContentsSigners ?: emptyArray()
            } else {
                @Suppress("DEPRECATION")
                val packageInfo = context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNATURES
                )
                @Suppress("DEPRECATION")
                packageInfo.signatures ?: emptyArray()
            }
            
            if (signatures.isNotEmpty()) {
                getSignatureHash(signatures[0])
            } else {
                null
            }
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Failed to get signature hash", e)
            null
        }
    }
    
    /**
     * Calculate SHA-256 hash of signature
     */
    private fun getSignatureHash(signature: android.content.pm.Signature): String {
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(signature.toByteArray())
        return digest.joinToString("") { "%02x".format(it) }
    }
    
    /**
     * Verify installer package
     * Checks if app was installed from legitimate source (Play Store)
     */
    fun verifyInstaller(context: Context): Boolean {
        return try {
            val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                context.packageManager.getInstallSourceInfo(context.packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getInstallerPackageName(context.packageName)
            }
            
            // Legitimate installer packages
            val legitimateInstallers = setOf(
                "com.android.vending",           // Google Play Store
                "com.google.android.feedback",    // Google Play (internal testing)
                "com.android.packageinstaller",   // System installer (for development)
                null                              // null is OK for debug builds
            )
            
            val isLegitimate = legitimateInstallers.contains(installer)
            
            if (!isLegitimate) {
                android.util.Log.w(TAG, "Suspicious installer: $installer")
            }
            
            isLegitimate
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Installer verification failed", e)
            false
        }
    }
    
    /**
     * Check if APK has been modified since installation
     * Detects runtime patching/hooking at file level
     */
    fun checkApkModification(context: Context): Boolean {
        return try {
            val packageInfo = context.packageManager.getPackageInfo(
                context.packageName,
                0
            )
            
            val apkPath = packageInfo.applicationInfo.sourceDir
            val apkFile = java.io.File(apkPath)
            
            // Check if APK file exists and is readable
            if (!apkFile.exists() || !apkFile.canRead()) {
                android.util.Log.w(TAG, "APK file not accessible")
                return false
            }
            
            // Check last modified time
            // In normal circumstances, APK shouldn't be modified after installation
            val lastModified = apkFile.lastModified()
            val installTime = packageInfo.firstInstallTime
            
            // Allow some tolerance (1 hour) for system updates
            val isModified = (lastModified - installTime) > 3600000
            
            if (isModified) {
                android.util.Log.w(TAG, "APK has been modified after installation")
            }
            
            !isModified
        } catch (e: Exception) {
            android.util.Log.e(TAG, "APK modification check failed", e)
            true // Assume safe if check fails
        }
    }
    
    /**
     * Comprehensive integrity check
     * Runs all integrity verifications
     */
    fun performIntegrityCheck(context: Context, expectedSignatureHash: String? = null): IntegrityResult {
        val signatureValid = verifySignature(context, expectedSignatureHash)
        val installerValid = verifyInstaller(context)
        val apkNotModified = checkApkModification(context)
        
        val passed = signatureValid && installerValid && apkNotModified
        
        return IntegrityResult(
            passed = passed,
            signatureValid = signatureValid,
            installerValid = installerValid,
            apkNotModified = apkNotModified
        )
    }
    
    /**
     * Calculate integrity score (0-100) - flag-less check
     * Higher score = better integrity
     */
    fun calculateIntegrityScore(context: Context, expectedSignatureHash: String? = null): Int {
        var score = 0
        
        // Signature check (40 points)
        if (verifySignature(context, expectedSignatureHash)) score += 40
        
        // Installer check (30 points)
        if (verifyInstaller(context)) score += 30
        
        // APK modification check (30 points)
        if (checkApkModification(context)) score += 30
        
        return score.coerceIn(0, 100)
    }
}

/**
 * Result of integrity check
 */
data class IntegrityResult(
    val passed: Boolean,
    val signatureValid: Boolean,
    val installerValid: Boolean,
    val apkNotModified: Boolean
) {
    fun getFailureReasons(): List<String> {
        val reasons = mutableListOf<String>()
        if (!signatureValid) reasons.add("Invalid APK signature - app may be repackaged")
        if (!installerValid) reasons.add("Invalid installer - app not from Play Store")
        if (!apkNotModified) reasons.add("APK file modified - possible tampering")
        return reasons
    }
}
