package com.secureguard.sdk.util

import android.app.Activity
import android.app.Application
import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.view.WindowManager

/**
 * Background Screen Security Helper
 * 
 * Protects sensitive information when app goes to background:
 * - Shows black overlay when minimized
 * - Prevents screenshot leakage in app switcher
 * - Blocks sensitive data visibility
 * 
 * Usage:
 * 1. In Application class: BackgroundSecurityHelper.register(this)
 * 2. Or per Activity: Add to onCreate()
 */
object BackgroundSecurityHelper {
    
    private var overlayView: View? = null
    
    /**
     * Register application-wide background security
     * Call this in Application.onCreate()
     */
    fun register(application: Application) {
        application.registerActivityLifecycleCallbacks(object : Application.ActivityLifecycleCallbacks {
            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
                // Prevent screenshots and screen recording
                preventScreenCapture(activity)
            }
            
            override fun onActivityStarted(activity: Activity) {}
            
            override fun onActivityResumed(activity: Activity) {
                // Remove black overlay when app comes to foreground
                removeBlackOverlay(activity)
            }
            
            override fun onActivityPaused(activity: Activity) {
                // Show black overlay when app goes to background
                showBlackOverlay(activity)
            }
            
            override fun onActivityStopped(activity: Activity) {}
            
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
            
            override fun onActivityDestroyed(activity: Activity) {
                removeBlackOverlay(activity)
            }
        })
    }
    
    /**
     * Prevent screenshots and screen recording
     * Call in Activity.onCreate()
     */
    fun preventScreenCapture(activity: Activity) {
        activity.window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
    }
    
    /**
     * Show black overlay when app goes to background
     * Prevents sensitive data from being visible in app switcher
     */
    private fun showBlackOverlay(activity: Activity) {
        try {
            if (overlayView == null) {
                overlayView = View(activity).apply {
                    setBackgroundColor(Color.BLACK)
                    layoutParams = WindowManager.LayoutParams(
                        WindowManager.LayoutParams.MATCH_PARENT,
                        WindowManager.LayoutParams.MATCH_PARENT
                    )
                }
            }
            
            // Add overlay to window
            val decorView = activity.window.decorView as? android.view.ViewGroup
            decorView?.let {
                if (overlayView?.parent == null) {
                    it.addView(overlayView)
                }
            }
        } catch (e: Exception) {
            android.util.Log.e("BackgroundSecurity", "Failed to show overlay", e)
        }
    }
    
    /**
     * Remove black overlay when app comes to foreground
     */
    private fun removeBlackOverlay(activity: Activity) {
        try {
            val decorView = activity.window.decorView as? android.view.ViewGroup
            decorView?.removeView(overlayView)
        } catch (e: Exception) {
            android.util.Log.e("BackgroundSecurity", "Failed to remove overlay", e)
        }
    }
    
    /**
     * Enable background security for a single activity
     * Call in Activity.onCreate()
     */
    fun enableForActivity(activity: Activity) {
        preventScreenCapture(activity)
        
        // Manual lifecycle management for single activity
        // Use register() for application-wide protection
    }
}
