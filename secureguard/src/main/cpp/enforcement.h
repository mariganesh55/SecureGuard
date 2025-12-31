#ifndef SECUREGUARD_ENFORCEMENT_H
#define SECUREGUARD_ENFORCEMENT_H

#include <jni.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

// Enforcement strategies - native owns the outcome
namespace enforcement {

    // Direct process termination - no managed layer involvement
    void terminate_process() {
        _exit(137); // Non-zero exit, looks like crash
    }

    // Corrupt critical memory to cause delayed crash
    void corrupt_state() {
        // Overwrite return addresses, corrupt heap
        volatile int* bad_ptr = nullptr;
        *bad_ptr = 0xDEADBEEF;
    }

    // Silent corruption - app continues but in broken state
    void silent_corruption() {
        // Corrupt function pointers, modify vtables
        // App appears to work but produces wrong results
    }

    // Delayed termination - makes it harder to identify cause
    void delayed_kill(int seconds) {
        sleep(seconds);
        raise(SIGSEGV); // Looks like segfault
    }

    // Random enforcement - unpredictable behavior
    void random_enforcement() {
        int strategy = rand() % 4;
        switch(strategy) {
            case 0: terminate_process(); break;
            case 1: delayed_kill(5); break;
            case 2: corrupt_state(); break;
            case 3: raise(SIGILL); break; // Illegal instruction
        }
    }

} // namespace enforcement

#endif // SECUREGUARD_ENFORCEMENT_H
