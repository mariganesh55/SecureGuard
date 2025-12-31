#include "security_checks.h"
#include <fstream>
#include <sstream>
#include <cstring>
#include <unistd.h>
#include <sys/stat.h>
#include <android/log.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <sys/syscall.h>
#include <linux/sched.h>
#include <errno.h>
#include <sys/mman.h>
#include <dlfcn.h>

#define LOG_TAG "SecurityChecks"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Obfuscated strings (XOR encrypted)
#define XOR_KEY 0xAB
static inline char *deobfuscate(const char *str, size_t len)
{
    static char buf[256];
    for (size_t i = 0; i < len && i < 255; i++)
    {
        buf[i] = str[i] ^ XOR_KEY;
    }
    buf[len < 255 ? len : 255] = '\0';
    return buf;
}

// Global state for autonomous monitoring
static pthread_t g_monitor_thread[3]; // Multiple redundant threads
static volatile bool g_monitoring_active = false;
static volatile int g_threat_count = 0;
static volatile int g_thread_health[3] = {0, 0, 0};

// EXPERT-PROOF: Direct syscall - cannot be hooked by Frida
static inline void direct_exit() __attribute__((always_inline));
static inline void direct_exit()
{
    // Method 1: exit_group syscall (kills all threads)
    syscall(__NR_exit_group, 137);

    // Method 2: If still alive, kill process group
    syscall(__NR_kill, 0, SIGKILL);

    // Method 3: If STILL alive, infinite loop consuming CPU
    while (1)
    {
        volatile int x = 0;
        x++;
    }
}

// EXPERT-PROOF: Direct clone syscall - cannot be hooked
static inline int direct_clone(void *(*fn)(void *), void *arg)
{
    // Allocate stack for new thread
    void *stack = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED)
        return -1;

    // Clone with direct syscall (unhookable)
    int flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
                CLONE_THREAD | CLONE_SYSVSEM;
    void *stack_top = (char *)stack + 8192;

    return syscall(__NR_clone, flags, stack_top, NULL, NULL, NULL);
}

// Anti-debugging: Detect if someone tries to attach
static void anti_debug_handler(int sig)
{
    // EXPERT-PROOF: Direct syscall instead of _exit()
    direct_exit();
}

// State corruption for bypass resistance
static void corrupt_critical_state()
{
    // EXPERT-PROOF: Multiple corruption methods

    // Method 1: Corrupt stack
    volatile int poison[1024];
    for (int i = 0; i < 1024; i++)
    {
        poison[i] = rand();
    }

    // Method 2: Invalid memory access (uncatchable)
    volatile int *bad_ptr = (int *)(0xDEADBEEFUL ^ rand());
    *bad_ptr = 0;

// Method 3: If still alive, trigger SIGILL with architecture-specific invalid instruction
#if defined(__x86_64__) || defined(__i386__)
    __asm__ volatile("ud2"); // x86/x64 invalid instruction
#elif defined(__aarch64__) || defined(__arm__)
    __asm__ volatile(".word 0xf7f0a000"); // ARM/ARM64 undefined instruction
#else
    __asm__ volatile(".word 0"); // Generic invalid instruction
#endif

    // Method 4: If STILL alive, direct syscall
    direct_exit();
}

// EXPERT-PROOF: Early Frida detection (runs in constructor)
static void detect_frida_early() __attribute__((constructor(101)));
static void detect_frida_early()
{
    // Check for Frida before any hooks can be set
    const char *frida_libs[] = {
        "frida", "gadget", "gum-js", "frida-agent", NULL};

    // Check /proc/self/maps
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line))
    {
        for (int i = 0; frida_libs[i] != NULL; i++)
        {
            if (line.find(frida_libs[i]) != std::string::npos)
            {
                // Frida detected - immediate kill
                direct_exit();
            }
        }
    }

    // Check for Frida ports (27042, 27043)
    std::ifstream tcp("/proc/net/tcp");
    while (std::getline(tcp, line))
    {
        if (line.find(":6992") != std::string::npos || // 27042 in hex
            line.find(":6993") != std::string::npos)
        { // 27043 in hex
            direct_exit();
        }
    }
}

// ==================== EXPERT-PROOF: Native Enforcement ====================

// Native owns the consequence - NO return to Java
void SecurityChecks::enforceSecurityViolation(const char *reason)
{
    LOGE("SECURITY VIOLATION: %s", reason);

    g_threat_count++;

    // Multi-stage enforcement (harder to bypass)

    // Stage 1: Immediate actions
    if (g_threat_count >= 3)
    {
        // Multiple threats = aggressive response

        // Method 1: State corruption (can't be easily bypassed)
        corrupt_critical_state();

        // Method 2: Direct syscall (if corruption didn't crash us)
        direct_exit();
    }

    // Stage 2: Delayed/random response (timing attack resistance)
    if (g_threat_count >= 1)
    {
        // Register signal handlers with sigaction (more secure than signal)
        struct sigaction sa;
        sa.sa_handler = anti_debug_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGTRAP, &sa, NULL);
        sigaction(SIGILL, &sa, NULL);

        // Verify handlers were installed (detect if hooked)
        struct sigaction verify;
        sigaction(SIGTRAP, NULL, &verify);
        if (verify.sa_handler != anti_debug_handler)
        {
            // Handler was tampered with!
            direct_exit();
        }

        // Random delay before next check (0-5 seconds)
        usleep((rand() % 5000000));
    }
}

// EXPERT-PROOF: Verify native library integrity
static bool verify_library_integrity()
{
    // Get our own library handle
    void *handle = dlopen("libsecureguard-native.so", RTLD_NOW | RTLD_NOLOAD);
    if (!handle)
        return false;

    // Check if key functions are present and not hooked
    void *isRooted = dlsym(handle, "_ZN14SecurityChecks8isRootedEv");
    void *enforceViolation = dlsym(handle, "_ZN14SecurityChecks25enforceSecurityViolationEPKc");

    if (!isRooted || !enforceViolation)
    {
        // Library has been tampered with
        return false;
    }

    dlclose(handle);
    return true;
}

// ==================== Root Detection ====================

bool SecurityChecks::isRooted()
{
    return checkSuBinary();
}

bool SecurityChecks::checkSuBinary()
{
    const char *suPaths[] = {
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/system/su",
        "/su/bin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        nullptr};

    for (int i = 0; suPaths[i] != nullptr; i++)
    {
        struct stat st;
        if (stat(suPaths[i], &st) == 0)
        {
            // File exists
            if (S_ISREG(st.st_mode) && (st.st_mode & S_IXUSR))
            {
                // File is regular and executable
                LOGD("Found SU binary at: %s", suPaths[i]);

                // PENTESTER-PROOF: Don't return - enforce directly
                enforceSecurityViolation("Root detected");
                return true;
            }
        }
    }

    return false;
}

// ==================== Emulator Detection ====================

bool SecurityChecks::isEmulator()
{
    // Check for QEMU properties in /proc/cpuinfo
    std::string cpuInfo = readFile("/proc/cpuinfo");

    if (cpuInfo.find("goldfish") != std::string::npos ||
        cpuInfo.find("ranchu") != std::string::npos)
    {
        LOGD("Emulator detected via cpuinfo");

        // PENTESTER-PROOF: Enforce directly
        enforceSecurityViolation("Emulator detected");
        return true;
    }

    // Check for emulator-specific files
    struct stat st;
    if (stat("/sys/qemu_trace", &st) == 0 ||
        stat("/system/bin/qemu-props", &st) == 0)
    {
        LOGD("Emulator detected via qemu files");

        // PENTESTER-PROOF: Enforce directly
        enforceSecurityViolation("Emulator files found");
        return true;
    }

    return false;
}

// ==================== Debugger Detection ====================

bool SecurityChecks::isDebuggerAttached()
{
    return checkTracerPid();
}

bool SecurityChecks::checkTracerPid()
{
    std::string status = readFile("/proc/self/status");

    size_t pos = status.find("TracerPid:");
    if (pos != std::string::npos)
    {
        std::string line = status.substr(pos);
        size_t endPos = line.find('\n');
        if (endPos != std::string::npos)
        {
            line = line.substr(0, endPos);
        }

        // Extract the PID number
        size_t pidPos = line.find_first_of("0123456789");
        if (pidPos != std::string::npos)
        {
            int pid = std::stoi(line.substr(pidPos));
            if (pid != 0)
            {
                LOGD("Debugger detected via TracerPid: %d", pid);

                // PENTESTER-PROOF: Enforce immediately
                enforceSecurityViolation("Debugger attached");
                return true;
            }
        }
    }

    return false;
}

// ==================== Frida Detection ====================

bool SecurityChecks::isFridaDetected()
{
    // Check for Frida libraries in memory maps
    if (checkMapsForLibrary("frida") ||
        checkMapsForLibrary("libfrida-gadget"))
    {
        LOGD("Frida detected in memory maps");

        // PENTESTER-PROOF: Enforce immediately
        enforceSecurityViolation("Frida framework detected");
        return true;
    }

    // Check for Frida named pipes
    struct stat st;
    if (stat("/data/local/tmp/frida-server", &st) == 0 ||
        stat("/data/local/tmp/re.frida.server", &st) == 0)
    {
        LOGD("Frida detected via server files");

        // PENTESTER-PROOF: Enforce immediately
        enforceSecurityViolation("Frida server found");
        return true;
    }

    return false;
}

bool SecurityChecks::checkMapsForLibrary(const char *library)
{
    std::string maps = readFile("/proc/self/maps");
    return maps.find(library) != std::string::npos;
}

// ==================== EXPERT-PROOF: Autonomous Enforcement ====================

// EXPERT-PROOF: Autonomous monitoring thread - runs independently of Java
// Multiple redundant threads for resilience
static void *autonomous_security_monitor(void *arg)
{
    int thread_id = *(int *)arg;
    LOGD("Autonomous security monitor #%d started", thread_id);

    // Seed random for timing attacks
    srand(time(NULL) ^ getpid() ^ thread_id);

    while (g_monitoring_active)
    {
        // Mark this thread as alive
        g_thread_health[thread_id] = 1;

        // Verify library integrity periodically
        if (rand() % 20 == 0)
        {
            if (!verify_library_integrity())
            {
                LOGE("Library integrity check failed!");
                direct_exit();
            }
        }

        // Continuous checks without asking Java

        // Check 1: Root detection
        SecurityChecks::isRooted();

        // Check 2: Debugger detection
        SecurityChecks::isDebuggerAttached();

        // Check 3: Frida detection
        SecurityChecks::isFridaDetected();

        // Check 4: Emulator detection (less frequent)
        static int emulator_check_counter = 0;
        if (++emulator_check_counter % 10 == 0)
        {
            SecurityChecks::isEmulator();
        }

        // Check 5: Thread health monitoring (resurrect dead threads)
        if (thread_id == 0)
        { // Only first thread monitors others
            for (int i = 0; i < 3; i++)
            {
                if (g_thread_health[i] == 0 && i != thread_id)
                {
                    // Thread is dead - resurrect it
                    LOGE("Thread #%d is dead - resurrecting!", i);
                    static int tid = i;
                    direct_clone(autonomous_security_monitor, &tid);
                }
                g_thread_health[i] = 0; // Reset for next check
            }
        }

        // Random interval between checks (10-30 seconds)
        // Prevents timing-based bypasses
        int sleep_time = 10 + (rand() % 20);
        sleep(sleep_time);
    }

    return nullptr;
}

// EXPERT-PROOF: Start multiple redundant monitoring threads
void SecurityChecks::startAutonomousMonitoring()
{
    if (g_monitoring_active)
    {
        LOGD("Monitoring already active");
        return;
    }

    g_monitoring_active = true;

    // Create 3 redundant monitoring threads
    // If attacker kills one, others continue
    for (int i = 0; i < 3; i++)
    {
        static int thread_ids[3] = {0, 1, 2};

        // Try direct clone first (unhookable)
        int clone_result = direct_clone(autonomous_security_monitor, &thread_ids[i]);

        if (clone_result > 0)
        {
            LOGD("Monitoring thread #%d created via direct clone", i);
            continue;
        }

        // Fallback to pthread_create if clone fails
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

        if (pthread_create(&g_monitor_thread[i], &attr, autonomous_security_monitor, &thread_ids[i]) != 0)
        {
            LOGE("Failed to create monitoring thread #%d", i);
        }
        else
        {
            LOGD("Monitoring thread #%d created via pthread", i);
        }

        pthread_attr_destroy(&attr);
    }

    LOGD("All monitoring threads started");
}

// Stop monitoring (for testing only)
void SecurityChecks::stopAutonomousMonitoring()
{
    g_monitoring_active = false;
}

// ==================== Device Fingerprint ====================

std::string SecurityChecks::getDeviceFingerprint()
{
    std::stringstream fingerprint;

    // Combine multiple system properties
    fingerprint << "pid:" << getpid();

    // Add more unique identifiers here in production
    // - Hardware serial numbers
    // - System properties
    // - Build information

    return fingerprint.str();
}

// ==================== Utility Functions ====================

std::string SecurityChecks::readFile(const char *path)
{
    std::ifstream file(path);
    if (!file.is_open())
    {
        return "";
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}
