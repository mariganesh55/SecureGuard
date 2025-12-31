#ifndef SECUREGUARD_SELF_PROTECT_H
#define SECUREGUARD_SELF_PROTECT_H

#include <dlfcn.h>
#include <link.h>
#include <string.h>
#include "enforcement.h"

// Self-protection: detect if native code itself is being hooked
namespace self_protect {

    // Check if our own functions are hooked
    bool is_function_hooked(void* func_ptr) {
        Dl_info info;
        if (dladdr(func_ptr, &info)) {
            // Check if function address is in unexpected library
            if (strstr(info.dli_fname, "frida") ||
                strstr(info.dli_fname, "substrate") ||
                strstr(info.dli_fname, "xposed")) {
                return true;
            }
        }
        return false;
    }

    // Verify JNI function pointers haven't been replaced
    void verify_jni_integrity(JNIEnv* env) {
        // Get JNI function table
        void** functions = (void**)env->functions;
        
        // Check if FindClass points to unexpected location
        Dl_info info;
        if (dladdr(functions[6], &info)) { // FindClass is at index 6
            const char* lib_name = info.dli_fname;
            // Should be in libart.so or libandroid_runtime.so
            if (!strstr(lib_name, "libart") && 
                !strstr(lib_name, "libandroid_runtime")) {
                // JNI table is hooked!
                enforcement::terminate_process();
            }
        }
    }

    // Check for common hooking libraries loaded
    static int check_loaded_lib(struct dl_phdr_info* info, size_t size, void* data) {
        const char* name = info->dlpi_name;
        if (name && strlen(name) > 0) {
            // Frida detection
            if (strstr(name, "frida") || 
                strstr(name, "gadget") ||
                strstr(name, "agent")) {
                enforcement::random_enforcement();
            }
            // Xposed detection
            if (strstr(name, "XposedBridge") ||
                strstr(name, "substrate") ||
                strstr(name, "dobby")) {
                enforcement::delayed_kill(1);
            }
        }
        return 0;
    }

    // Scan all loaded libraries
    void scan_loaded_libraries() {
        dl_iterate_phdr(check_loaded_lib, nullptr);
    }

    // Verify our own code integrity
    void verify_self_integrity() {
        // Check if our .text section is writable (shouldn't be)
        FILE* maps = fopen("/proc/self/maps", "r");
        if (maps) {
            char line[512];
            while (fgets(line, sizeof(line), maps)) {
                if (strstr(line, "libsecureguard") && 
                    strstr(line, "rwx")) { // Should be r-x, not rwx
                    fclose(maps);
                    enforcement::corrupt_state();
                }
            }
            fclose(maps);
        }
    }

    // Initialize self-protection
    void initialize(JNIEnv* env) {
        verify_jni_integrity(env);
        scan_loaded_libraries();
        verify_self_integrity();
        // No return - just enforces
    }

} // namespace self_protect

#endif // SECUREGUARD_SELF_PROTECT_H
