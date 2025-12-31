#ifndef SECUREGUARD_CONTINUOUS_MONITOR_H
#define SECUREGUARD_CONTINUOUS_MONITOR_H

#include <pthread.h>
#include <unistd.h>
#include <jni.h>
#include "enforcement.h"

// Continuous monitoring thread that runs independently
// Managed layer cannot stop this once started
namespace monitor {

    static volatile bool should_monitor = true;
    static pthread_t monitor_thread;

    // Thread function - runs continuously
    static void* monitor_loop(void* arg) {
        while (should_monitor) {
            // Random delay to avoid pattern detection
            int delay = 5 + (rand() % 10); // 5-15 seconds
            sleep(delay);

            // Check root indicators
            if (access("/system/bin/su", F_OK) == 0) {
                enforcement::random_enforcement();
            }

            // Check debugger
            FILE* status = fopen("/proc/self/status", "r");
            if (status) {
                char line[256];
                while (fgets(line, sizeof(line), status)) {
                    if (strncmp(line, "TracerPid:", 10) == 0) {
                        int pid = atoi(line + 10);
                        if (pid != 0) {
                            fclose(status);
                            enforcement::delayed_kill(2);
                        }
                    }
                }
                fclose(status);
            }

            // Check Frida ports
            FILE* tcp = fopen("/proc/net/tcp", "r");
            if (tcp) {
                char line[512];
                while (fgets(line, sizeof(line), tcp)) {
                    // Look for Frida default port 27042 (0x69C2)
                    if (strstr(line, "69C2") || strstr(line, "6A52")) {
                        fclose(tcp);
                        enforcement::terminate_process();
                    }
                }
                fclose(tcp);
            }

            // Check for Frida libraries in memory maps
            FILE* maps = fopen("/proc/self/maps", "r");
            if (maps) {
                char line[512];
                while (fgets(line, sizeof(line), maps)) {
                    if (strstr(line, "frida") || 
                        strstr(line, "gadget") ||
                        strstr(line, "linjector")) {
                        fclose(maps);
                        enforcement::corrupt_state();
                    }
                }
                fclose(maps);
            }
        }
        return nullptr;
    }

    // Start monitoring - called once, runs forever
    void start_monitoring() {
        pthread_create(&monitor_thread, nullptr, monitor_loop, nullptr);
        pthread_detach(monitor_thread); // Runs independently
    }

    // This function never returns anything to managed layer
    // It just starts and enforces on its own
    void initialize() {
        start_monitoring();
        // No return value - managed layer doesn't know what's happening
    }

} // namespace monitor

#endif // SECUREGUARD_CONTINUOUS_MONITOR_H
