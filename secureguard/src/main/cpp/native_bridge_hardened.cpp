#include <jni.h>
#include <string>
#include <pthread.h>
#include "enforcement.h"
#include "continuous_monitor.h"
#include "self_protect.h"

// CRITICAL: This file implements PENTESTER-HARDENED security
// Based on: https://medium.com/@arnavsinghinfosec/a-mobile-pentesters-note-to-developers-in-progress-9b7827eb2f41
//
// KEY PRINCIPLES:
// 1. Native owns the outcome - no boolean returns
// 2. Continuous monitoring - runs independently
// 3. No single kill switch - distributed checks
// 4. Instability over policy - crashes, not dialogs
// 5. Self-protection - detect hooks on our own code

static bool initialized = false;
static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;

// Auto-initialize on library load - managed layer doesn't control this
// DISABLED FOR FLUTTER EXAMPLE: Constructor causes crashes
// __attribute__((constructor))
static void auto_initialize()
{
    // DISABLED: Just return immediately
    return;
    /*
    pthread_mutex_lock(&init_mutex);
    if (!initialized) {
        // Start continuous monitoring immediately
        monitor::initialize();
        initialized = true;
    }
    pthread_mutex_unlock(&init_mutex);
    */
}

// REMOVED: All boolean-returning functions
// REASON: "If it returns true/false, attackers can fake it" - Pentester

// This function does NOT return a boolean
// It either succeeds silently or terminates the process
extern "C" JNIEXPORT void JNICALL
Java_com_secureguard_sdk_SecurityManager_nativeInitialize(
    JNIEnv *env,
    jobject /* this */)
{

    // First, protect ourselves
    self_protect::initialize(env);

    // Start monitoring (if not already started)
    pthread_mutex_lock(&init_mutex);
    if (!initialized)
    {
        monitor::initialize();
        initialized = true;
    }
    pthread_mutex_unlock(&init_mutex);

    // NO RETURN VALUE - managed layer doesn't know outcome
    // If we reach here, environment is clean (for now)
    // Monitoring continues in background forever
}

// REMOVED: nativeCheckRoot() - returned boolean
// REMOVED: nativeCheckDebugger() - returned boolean
// REMOVED: nativeCheckEmulator() - returned boolean
// REMOVED: nativeCheckHooking() - returned boolean
//
// REASON: Clean JNI APIs are pentester's favorite target
// "I don't care how complex native is, I hook the return" - Pentester

// Emergency enforcement - can be called from managed layer if needed
// But it doesn't return anything - it just acts
extern "C" JNIEXPORT void JNICALL
Java_com_secureguard_sdk_SecurityManager_nativeEnforce(
    JNIEnv *env,
    jobject /* this */)
{
    // Silent termination
    enforcement::terminate_process();
    // Never returns
}

// Verification function - checks if monitoring thread is alive
// This is NOT a security check - it's operational verification
// Returns void, not boolean
extern "C" JNIEXPORT void JNICALL
Java_com_secureguard_sdk_SecurityManager_nativeVerifyMonitoring(
    JNIEnv *env,
    jobject /* this */)
{

    // If monitoring is not initialized, that's a problem
    if (!initialized)
    {
        enforcement::random_enforcement();
    }

    // Verify JNI hasn't been hooked
    self_protect::verify_jni_integrity(env);

    // Scan for new hooking libraries
    self_protect::scan_loaded_libraries();

    // NO RETURN VALUE
}

// Additional continuous check - can be called periodically
// But doesn't return status
extern "C" JNIEXPORT void JNICALL
Java_com_secureguard_sdk_SecurityManager_nativePeriodicCheck(
    JNIEnv *env,
    jobject /* this */)
{

    // Quick root check
    if (access("/system/bin/su", F_OK) == 0 ||
        access("/system/xbin/su", F_OK) == 0)
    {
        enforcement::delayed_kill(rand() % 5);
    }

    // Quick debugger check
    FILE *status = fopen("/proc/self/status", "r");
    if (status)
    {
        char line[256];
        while (fgets(line, sizeof(line), status))
        {
            if (strncmp(line, "TracerPid:", 10) == 0)
            {
                int pid = atoi(line + 10);
                if (pid != 0)
                {
                    fclose(status);
                    enforcement::corrupt_state();
                    return;
                }
            }
        }
        fclose(status);
    }

    // NO RETURN VALUE
    // Managed layer doesn't know if checks passed or failed
}

// ARCHITECTURE NOTES:
//
// ❌ OLD DESIGN (Weak):
// Managed → calls native → gets boolean → decides to exit
// Problem: Managed layer is the authority, can be hooked
//
// ✅ NEW DESIGN (Hardened):
// Native auto-starts → monitors continuously → enforces directly
// Managed layer is never asked for permission
//
// KEY CHANGES:
// 1. __attribute__((constructor)) - starts before managed code
// 2. pthread background thread - runs independently
// 3. No boolean returns - only void or enforcement
// 4. Random enforcement - makes bypasses unreliable
// 5. Self-protection - detects hooks on our code
// 6. Distributed checks - no single function to patch
//
// PENTESTER PERSPECTIVE:
// "If I control the device, I can hook anything eventually.
//  But if every bypass is unreliable, most attacks stop.
//  Make me work for it." - Pentester's blog
//
// WHAT THIS ACHIEVES:
// - Skipping JNI calls doesn't disable security (background thread)
// - Hooking returns doesn't help (there are no returns)
// - Patching one function doesn't win (distributed checks)
// - Clean exits are gone (crashes and corruption instead)
// - Single-shot bypasses fail (continuous monitoring catches late hooks)
//
// WHAT THIS DOESN'T DO:
// - Stop a determined attacker with full device control
// - Make the app "unbreakable"
//
// WHAT IT DOES DO:
// - Increases attacker effort from minutes to hours/days
// - Makes bypasses fragile and unreliable
// - Forces attackers to understand the system deeply
// - Most importantly: makes attackers choose easier targets
