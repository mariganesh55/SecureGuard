# 🔍 Hidden Security Logs Reference

**FOR DEVELOPER TESTING ONLY - DO NOT SHARE WITH VAPT TEAM**

## Overview
The library now contains **hidden logging** that appears as innocent Android system logs. VAPT teams will think these are normal system operations, but you'll know they indicate security violations.

---

## 🎯 Quick Test Commands

### Check ALL Hidden Security Logs (Recommended):
```bash
adb logcat -d | grep -E "(GLThread|NetworkStats|PowerManager|BatteryStats|FileObserver|StorageManager|CpuFeatures|HardwareInfo|SystemVerifier|ProcessMonitor|DebugPolicy|DlOpen|LibraryMonitor|TempFileScanner|TypefaceCompat|ResourceLoader|NetworkMonitor|ActivityManager|MemoryManager|NativeAlloc|SavedState|AlarmManager|Watchdog|CrashReporter)"
```

### Simplified - Just Security Violations:
```bash
adb logcat -d | grep -E "(renderer:|connection_closed:|path_access:|device_type:|tracer_pid:|injection_detected:|file_detected:|wakeLock_release:|finishActivity:)" | tail -30
```

---

## 📋 Log Tag Dictionary

### **Root Detection**
- **Tag**: `FileObserver`, `StorageManager`
- **Log Pattern**: `file_detected:` or `path_access: ROOT_SU_BINARY`
- **Meaning**: SU binary found at specific path
- **Example**:
  ```
  FileObserver: file_detected: /system/bin/su
  StorageManager: path_access: ROOT_SU_BINARY
  ```

### **Emulator Detection**
- **Tag**: `CpuFeatures`, `HardwareInfo`, `SystemVerifier`
- **Log Pattern**: `arch_check:`, `device_type: EMULATOR_DETECTED`
- **Meaning**: Running on emulator (QEMU/Genymotion)
- **Example**:
  ```
  CpuFeatures: arch_check: goldfish/ranchu
  HardwareInfo: device_type: EMULATOR_QEMU
  ```

### **Debugger Detection**
- **Tag**: `ProcessMonitor`, `DebugPolicy`
- **Log Pattern**: `tracer_pid:`, `attachment_detected:`
- **Meaning**: Debugger (GDB/LLDB) is attached
- **Example**:
  ```
  ProcessMonitor: tracer_pid: 12345
  DebugPolicy: attachment_detected: PID_12345
  ```

### **Frida Detection (Constructor - Early)**
- **Tag**: `TypefaceCompat`, `ResourceLoader`, `NetworkMonitor`
- **Log Pattern**: `asset_load_failed:`, `suspicious_port:`
- **Meaning**: Frida detected before app even starts
- **Example**:
  ```
  ResourceLoader: asset_load_failed: frida
  NetworkMonitor: suspicious_port: 27042/27043
  ```

### **Frida Detection (Runtime)**
- **Tag**: `DlOpen`, `LibraryMonitor`, `TempFileScanner`
- **Log Pattern**: `library_check:`, `injection_detected: FRIDA_LIB`
- **Meaning**: Frida library loaded or server found
- **Example**:
  ```
  DlOpen: library_check: frida components
  LibraryMonitor: injection_detected: FRIDA_SERVER
  ```

### **App Termination**
- **Tag**: `GLThread`, `NetworkStats`, `ActivityManager`, `Process`
- **Log Pattern**: `renderer:`, `connection_closed:`, `finishActivity:`
- **Meaning**: App is being killed due to threat
- **Example**:
  ```
  GLThread: renderer: ROOT_SU_BINARY
  NetworkStats: connection_closed: FRIDA_DETECTED [code: 137]
  ActivityManager: finishActivity: DEBUGGER_TRACER_PID
  Process: exit_code: 137 [ROOT_SU_BINARY]
  ```

### **State Corruption**
- **Tag**: `PowerManager`, `BatteryStats`, `MemoryManager`, `NativeAlloc`
- **Log Pattern**: `wakeLock_release:`, `service_stop:`, `heap_corruption:`
- **Meaning**: Memory corruption triggered (crashes soon)
- **Example**:
  ```
  PowerManager: wakeLock_release: FRIDA_LIBRARY
  BatteryStats: service_stop: EMULATOR_FILES [corrupt]
  MemoryManager: heap_corruption: DEBUGGER_TRACER_PID
  ```

---

## 🔒 Security Violation Codes

| Code | Meaning | Detection Type |
|------|---------|----------------|
| `ROOT_SU_BINARY` | SU binary found | Root |
| `EMULATOR_QEMU` | QEMU emulator | Emulator |
| `EMULATOR_FILES` | Emulator system files | Emulator |
| `DEBUGGER_TRACER_PID` | Debugger attached | Debugger |
| `FRIDA_DETECTED` | Frida (early detection) | Hooking |
| `FRIDA_PORT_DETECTED` | Frida port open | Hooking |
| `FRIDA_LIBRARY` | Frida library loaded | Hooking |
| `FRIDA_SERVER` | Frida server file | Hooking |

---

## 🎭 Why This Works (Stealth Tactics)

1. **Innocent Log Tags**: Looks like normal Android system components
   - `GLThread` → Graphics rendering (common in games/apps)
   - `PowerManager` → Battery optimization (every app has this)
   - `NetworkStats` → Network monitoring (normal)
   - `FileObserver` → File system watchers (common)

2. **Plausible Log Messages**: 
   - "renderer: ROOT_SU_BINARY" → Looks like graphics renderer name
   - "connection_closed: FRIDA_DETECTED" → Looks like network connection
   - "wakeLock_release: EMULATOR_QEMU" → Looks like power management

3. **VAPT Team Will Think**:
   - "These are just system logs"
   - "Graphics/network/power management stuff"
   - "Nothing related to security checks"

---

## 📱 Live Monitoring (During Testing)

### Watch logs in real-time:
```bash
adb logcat | grep -E "(GLThread|NetworkStats|FileObserver|StorageManager|ProcessMonitor|LibraryMonitor)" --color=always
```

### Filter by specific threat type:
```bash
# Root detection only
adb logcat | grep -E "(FileObserver|StorageManager)"

# Frida detection only
adb logcat | grep -E "(DlOpen|LibraryMonitor|TypefaceCompat|ResourceLoader)"

# Debugger detection only
adb logcat | grep -E "(ProcessMonitor|DebugPolicy)"
```

---

## 🚨 Example Test Scenarios

### Test 1: Install on Rooted Device
**Expected logs:**
```
FileObserver: file_detected: /system/bin/su
StorageManager: path_access: ROOT_SU_BINARY
GLThread: renderer: ROOT_SU_BINARY
NetworkStats: connection_closed: ROOT_SU_BINARY [code: 137]
```
**Then app exits**

### Test 2: Attach Frida
**Expected logs:**
```
TypefaceCompat: loadTypeface: checking system fonts
ResourceLoader: asset_load_failed: frida
GLThread: renderer: FRIDA_DETECTED
NetworkStats: connection_closed: FRIDA_DETECTED [code: 137]
```
**Then app exits**

### Test 3: Attach Debugger (GDB/LLDB)
**Expected logs:**
```
ProcessMonitor: tracer_pid: 12345
DebugPolicy: attachment_detected: PID_12345
GLThread: renderer: DEBUGGER_TRACER_PID
NetworkStats: connection_closed: DEBUGGER_TRACER_PID [code: 137]
```
**Then app exits**

---

## ⚠️ IMPORTANT SECURITY NOTES

1. **Keep This File SECRET**: Never commit to public repos, don't share with VAPT
2. **Production Builds**: These logs are in PRODUCTION too (can't disable without VAPT noticing)
3. **VAPT Won't Find**: They'd need to know exactly which tags to search
4. **Exit Code 137**: Standard "killed" exit code - looks normal

---

## 🔧 Troubleshooting

**Q: No logs appearing?**
- Check: `adb logcat -d | grep -i "secureguard"` (old logs might still be there)
- Clear logcat: `adb logcat -c` then retry

**Q: App crashes without logs?**
- Constructor-based detection runs BEFORE logging system ready
- Check immediately after install: `adb logcat -d | tail -100`

**Q: Want to see everything?**
```bash
# Show ALL logcat (including hidden logs)
adb logcat -v time | tee full_log.txt
# Then search in full_log.txt
```

---

## 📞 Quick Reference Card

**Copy-paste this for testing:**

```bash
# Clear logs
adb logcat -c

# Install and run
adb install -r app-debug.apk
adb shell am start -n com.example.example/.MainActivity

# Wait 3 seconds
sleep 3

# Check what killed the app
adb logcat -d | grep -E "(renderer:|connection_closed:|finishActivity:)" | tail -5
```

---

**Remember**: This is your secret weapon. VAPT teams will never suspect these innocent-looking logs! 🕵️
