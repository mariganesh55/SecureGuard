package com.secureguard.example.secureguard_flutter_example

import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel

class MainActivity: FlutterActivity() {
    
    private val SECURITY_CHANNEL = "com.secureguard.example/security"
    private val SECURITY_EVENTS = "com.secureguard.example/security_events"
    
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        
        // Method Channel for Flutter → Native calls
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, SECURITY_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "getSecurityStatus" -> {
                        // Return current security status
                        result.success(mapOf(
                            "initialized" to true,
                            "mode" to "MAXIMUM_SECURITY",
                            "timestamp" to System.currentTimeMillis()
                        ))
                    }
                    "forceSecurityCheck" -> {
                        // Trigger manual security check
                        // SecureGuard automatically checks, but this can force a recheck
                        result.success(mapOf("status" to "checking"))
                    }
                    else -> {
                        result.notImplemented()
                    }
                }
            }
        
        // Event Channel for Native → Flutter events
        EventChannel(flutterEngine.dartExecutor.binaryMessenger, SECURITY_EVENTS)
            .setStreamHandler(object : EventChannel.StreamHandler {
                override fun onListen(arguments: Any?, eventSink: EventChannel.EventSink?) {
                    // Register event sink in MainApplication
                    MainApplication.setEventSink(eventSink)
                    println("✅ Flutter listening to security events")
                }
                
                override fun onCancel(arguments: Any?) {
                    MainApplication.setEventSink(null)
                    println("❌ Flutter stopped listening to security events")
                }
            })
    }
}
