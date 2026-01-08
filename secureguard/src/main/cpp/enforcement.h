#ifndef SECUREGUARD_ENFORCEMENT_H
#define SECUREGUARD_ENFORCEMENT_H

#include <jni.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

// Enforcement strategies - native owns the outcome
namespace enforcement
{

    // Direct process termination - no managed layer involvement
    void terminate_process(const char *reason = "SECURITY_VIOLATION")
    {
        // Hidden log: Looks like ActivityManager
        __android_log_print(ANDROID_LOG_INFO, "ActivityManager", "finishActivity: %s", reason);
        __android_log_print(ANDROID_LOG_DEBUG, "Process", "exit_code: 137 [%s]", reason);
        _exit(137); // Non-catchable exit
    }

    // Corrupt critical memory to cause delayed crash
    void corrupt_state(const char *reason = "STATE_CORRUPT")
    {
        // Hidden log: Looks like memory management
        __android_log_print(ANDROID_LOG_WARN, "MemoryManager", "heap_corruption: %s", reason);
        __android_log_print(ANDROID_LOG_DEBUG, "NativeAlloc", "invalid_ptr: 0xDEADBEEF");
        volatile int *bad_ptr = nullptr;
        *bad_ptr = 0xDEADBEEF; // Segmentation fault
    }

    // Silent corruption - app continues but in broken state
    void silent_corruption(const char *reason = "SILENT")
    {
        // Hidden log: Looks like state save/restore
        __android_log_print(ANDROID_LOG_VERBOSE, "SavedState", "restore_failed: %s", reason);
        // Intentionally subtle - just corrupt some memory
        static int critical_state = 0;
        critical_state = 0xBADC0DE;
    }

    // Delayed termination - makes it harder to identify cause
    void delayed_kill(int seconds, const char *reason = "DELAYED_EXIT")
    {
        // Hidden log: Looks like timer/alarm
        __android_log_print(ANDROID_LOG_DEBUG, "AlarmManager", "alarm_set: %d seconds", seconds);
        __android_log_print(ANDROID_LOG_INFO, "Watchdog", "timeout_trigger: %s", reason);
        sleep(seconds);
        raise(SIGSEGV);
    }

    // Random enforcement - unpredictable behavior
    void random_enforcement(const char *reason = "RANDOM")
    {
        // Hidden log: Looks like crash reporter
        __android_log_print(ANDROID_LOG_WARN, "CrashReporter", "exception_handler: %s", reason);
        int strategy = rand() % 4;
        switch (strategy)
        {
        case 0:
            terminate_process(reason);
            break;
        case 1:
            delayed_kill(5, reason);
            break;
        case 2:
            corrupt_state(reason);
            break;
        case 3:
            raise(SIGILL);
            break; // Illegal instruction
        }
    }

} // namespace enforcement

#endif // SECUREGUARD_ENFORCEMENT_H
