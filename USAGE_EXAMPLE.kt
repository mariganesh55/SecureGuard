package com.example.myapp

import android.app.Application
import android.os.Process
import android.widget.Toast
import com.secureguard.sdk.SecureGuard
import com.secureguard.sdk.SecurityCallback
import com.secureguard.sdk.SecurityConfig
import com.secureguard.sdk.ThreatType

/**
 * Example Application class showing SecureGuard integration
 * 
 * Add this class to your app's AndroidManifest.xml:
 * <application
 *     android:name=".MyApplication"
 *     ...>
 */
class MyApplication : Application() {
    
    override fun onCreate() {
        super.onCreate()
        
        // Initialize SecureGuard with maximum security
        initializeSecureGuard()
    }
    
    private fun initializeSecureGuard() {
        val config = if (BuildConfig.DEBUG) {
            // Development mode - relaxed checks for testing
            SecurityConfig.developmentMode()
        } else {
            // Production mode - maximum security
            SecurityConfig.maximumSecurity().copy(
                alertMessage = "Security threat detected. This app cannot run on compromised devices.",
                monitoringInterval = 60000L // Check every minute
            )
        }
        
        SecureGuard.initialize(
            application = this,
            config = config,
            callback = object : SecurityCallback {
                
                override fun onThreatDetected(threatType: ThreatType, description: String) {
                    // Handle specific threats
                    when (threatType) {
                        ThreatType.ROOT_DETECTED -> {
                            handleRootDetection(description)
                        }
                        ThreatType.EMULATOR_DETECTED -> {
                            handleEmulatorDetection(description)
                        }
                        ThreatType.DEBUGGER_DETECTED -> {
                            handleDebuggerDetection(description)
                        }
                        ThreatType.HOOKING_DETECTED -> {
                            handleHookingDetection(description)
                        }
                        else -> {
                            handleUnknownThreat(description)
                        }
                    }
                }
                
                override fun onSecurityCheckComplete(passed: Boolean, threats: List<ThreatType>) {
                    if (passed) {
                        // Security checks passed - continue normal operation
                        onSecurityCheckPassed()
                    } else {
                        // Security checks failed - handle threats
                        onSecurityCheckFailed(threats)
                    }
                }
                
                override fun onAppShouldTerminate() {
                    // Critical threat detected - terminate app
                    terminateApp()
                }
            }
        )
    }
    
    private fun handleRootDetection(description: String) {
        // Log to analytics
        logSecurityEvent("root_detected", description)
        
        // Show alert to user
        showSecurityAlert("Root Detected", 
            "This app cannot run on rooted devices for security reasons.")
        
        // Terminate app after delay
        terminateApp()
    }
    
    private fun handleEmulatorDetection(description: String) {
        logSecurityEvent("emulator_detected", description)
        
        showSecurityAlert("Emulator Detected",
            "This app cannot run on emulators.")
        
        terminateApp()
    }
    
    private fun handleDebuggerDetection(description: String) {
        logSecurityEvent("debugger_detected", description)
        
        // Don't show alert to avoid tipping off attacker
        terminateApp()
    }
    
    private fun handleHookingDetection(description: String) {
        logSecurityEvent("hooking_detected", description)
        
        showSecurityAlert("Security Threat",
            "Unauthorized modification detected.")
        
        terminateApp()
    }
    
    private fun handleUnknownThreat(description: String) {
        logSecurityEvent("unknown_threat", description)
        terminateApp()
    }
    
    private fun onSecurityCheckPassed() {
        // Continue with app initialization
        // Initialize other SDKs, load user data, etc.
    }
    
    private fun onSecurityCheckFailed(threats: List<ThreatType>) {
        // Multiple threats detected
        val threatNames = threats.joinToString(", ") { it.description }
        logSecurityEvent("multiple_threats", threatNames)
        
        showSecurityAlert("Security Threats Detected",
            "Multiple security issues detected: $threatNames")
        
        terminateApp()
    }
    
    private fun showSecurityAlert(title: String, message: String) {
        // In production, show a proper AlertDialog
        Toast.makeText(this, "$title: $message", Toast.LENGTH_LONG).show()
    }
    
    private fun terminateApp() {
        // Give user time to read the message
        android.os.Handler(mainLooper).postDelayed({
            // Terminate the app
            Process.killProcess(Process.myPid())
            System.exit(1)
        }, 3000) // 3 second delay
    }
    
    private fun logSecurityEvent(event: String, details: String) {
        // Log to your analytics service
        // Example: Firebase Analytics, Crashlytics, etc.
        android.util.Log.w("SecureGuard", "Security Event: $event - $details")
        
        // In production:
        // FirebaseAnalytics.getInstance(this).logEvent(event, Bundle().apply {
        //     putString("details", details)
        // })
    }
}

/**
 * Example Activity showing manual security checks
 */
class MainActivity : AppCompatActivity() {
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        // Manual security check when needed
        performSecurityCheck()
    }
    
    private fun performSecurityCheck() {
        val secureGuard = SecureGuard.getInstance()
        
        if (secureGuard == null) {
            // SDK not initialized
            Toast.makeText(this, "Security SDK not initialized", Toast.LENGTH_SHORT).show()
            return
        }
        
        // Individual checks
        val isRooted = secureGuard.isRooted()
        val isEmulator = secureGuard.isEmulator()
        val isDebugging = secureGuard.isDebugging()
        val hookingFramework = secureGuard.detectHooking()
        
        // Display results
        val results = buildString {
            appendLine("Security Check Results:")
            appendLine("Rooted: ${if (isRooted) "⚠️ YES" else "✓ NO"}")
            appendLine("Emulator: ${if (isEmulator) "⚠️ YES" else "✓ NO"}")
            appendLine("Debugging: ${if (isDebugging) "⚠️ YES" else "✓ NO"}")
            if (hookingFramework != null) {
                appendLine("Hooking: ⚠️ $hookingFramework detected")
            } else {
                appendLine("Hooking: ✓ None detected")
            }
        }
        
        Toast.makeText(this, results, Toast.LENGTH_LONG).show()
        
        // If any threat detected, show alert
        if (isRooted || isEmulator || isDebugging || hookingFramework != null) {
            showSecurityWarning()
        }
    }
    
    private fun showSecurityWarning() {
        AlertDialog.Builder(this)
            .setTitle("Security Warning")
            .setMessage("One or more security threats have been detected. The app may not function properly.")
            .setPositiveButton("OK") { dialog, _ ->
                dialog.dismiss()
                finish()
            }
            .setCancelable(false)
            .show()
    }
    
    override fun onDestroy() {
        super.onDestroy()
        
        // Cleanup when no longer needed (optional)
        // SecureGuard.getInstance()?.destroy()
    }
}
