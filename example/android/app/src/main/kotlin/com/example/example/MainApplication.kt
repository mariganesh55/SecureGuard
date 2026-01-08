package com.example.example

import android.app.Application
import com.secureguard.sdk.SecureGuard
import com.secureguard.sdk.SecurityConfig

class MainApplication : Application() {
    
    override fun onCreate() {
        super.onCreate()
        
        // PRODUCTION: Just initialize - native handles everything
        // If this line executes, device passed all security checks
        SecureGuard.initialize(
            application = this,
            config = SecurityConfig.productionMode(), // Use production defaults
            callback = null  // No callback needed - native terminates before callback runs
        )
        
        // If execution reaches here, device is secure
        android.util.Log.i("SecureGuard", "✅ Security checks passed - App starting")
    }
}
