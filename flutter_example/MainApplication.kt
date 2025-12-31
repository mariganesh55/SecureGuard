package com.secureguard.example.secureguard_flutter_example

import android.app.Application
import com.secureguard.sdk.SecureGuard
import com.secureguard.sdk.SecurityCallback
import com.secureguard.sdk.SecurityConfig
import com.secureguard.sdk.ThreatType
import com.secureguard.sdk.util.BackgroundSecurityHelper
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel

class MainApplication : Application(), SecurityCallback {
    
    companion object {
        private var eventSink: EventChannel.EventSink? = null
        
        fun setEventSink(sink: EventChannel.EventSink?) {
            eventSink = sink
        }
    }
    
    override fun onCreate() {
        super.onCreate()
        
        // Initialize SecureGuard
        SecureGuard.initialize(
            application = this,
            config = SecurityConfig.maximumSecurity(),
            callback = this
        )
        
        // Enable background screen security
        BackgroundSecurityHelper.register(this)
        
        println("✅ SecureGuard initialized in MainApplication")
    }
    
    override fun onThreatDetected(threatType: ThreatType, description: String) {
        println("🚨 THREAT DETECTED: $threatType - $description")
        
        // Send threat to Flutter
        eventSink?.success(mapOf(
            "type" to "threat",
            "threatType" to threatType.name,
            "description" to description,
            "timestamp" to System.currentTimeMillis()
        ))
        
        // For critical threats, force exit after delay
        if (threatType in listOf(
            ThreatType.ROOT_DETECTED,
            ThreatType.EMULATOR_DETECTED,
            ThreatType.DEBUGGER_DETECTED
        )) {
            // Give Flutter time to show the message
            android.os.Handler(mainLooper).postDelayed({
                android.os.Process.killProcess(android.os.Process.myPid())
            }, 3000)
        }
    }
    
    override fun onSecurityCheckComplete(passed: Boolean, threats: List<ThreatType>) {
        println("✅ Security check complete. Passed: $passed, Threats: ${threats.size}")
        
        // Send status to Flutter
        eventSink?.success(mapOf(
            "type" to "status",
            "passed" to passed,
            "threats" to threats.map { it.name },
            "timestamp" to System.currentTimeMillis()
        ))
    }
}
