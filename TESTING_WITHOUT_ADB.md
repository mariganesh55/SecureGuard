# 🔍 Testing SecureGuard Without ADB/Developer Mode

## The Problem
Once you disable developer mode, you can't use `adb logcat` to see why the app exits.

## ✅ Solution: Hidden Debug Log File

The library now writes a hidden debug log to:
```
/sdcard/Download/.sg_debug.txt
```

---

## 📱 How to Test

### Step 1: Install the App (Developer Mode ON)
```bash
cd /Users/mariganesh/Documents/Projects/SecureGuard/example
flutter build apk --release
adb install -r build/app/outputs/flutter-apk/app-release.apk
```

### Step 2: Clear Old Logs
```bash
adb shell rm /sdcard/Download/.sg_debug.txt
```

### Step 3: Launch App and Let It Run
```bash
adb shell am start -n com.example.example/.MainActivity
# App will exit if threats detected
sleep 5
```

### Step 4: Check Logs (While ADB Still Works)
```bash
adb pull /sdcard/Download/.sg_debug.txt ~/Desktop/
cat ~/Desktop/.sg_debug.txt
```

### Step 5: Now Disable Developer Mode
1. Go to Settings → Developer Options → Turn OFF
2. Or disable USB Debugging

### Step 6: Launch App Again (No ADB This Time)
Just tap the app icon normally

### Step 7: Check Logs Manually on Phone
1. Open **Files** or **My Files** app
2. Navigate to **Downloads** folder
3. Enable "Show hidden files" (usually in ⋮ menu)
4. Find `.sg_debug.txt`
5. Open with any text viewer

---

## 📋 What the Log Contains

Example log file:
```
[1736356873] CHECK: Developer mode
[1736356873] DETECTED: ADB socket exists
[1736356873] EXIT: ADB_ENABLED
```

Or if clean:
```
[1736356920] CHECK: Developer mode
[1736356920] PASS: Developer mode check
[1736356920] CHECK: Root detection
[1736356920] PASS: Root check
```

---

## 🔎 Log Format

Each line contains:
- **Timestamp**: Unix timestamp (seconds since 1970)
- **Message**: What was checked and result

### Key Messages:

| Message | Meaning |
|---------|---------|
| `CHECK: Developer mode` | Starting developer mode check |
| `DETECTED: ADB socket exists` | Found `/dev/socket/adbd` |
| `DETECTED: /data/local/tmp is world-writable` | Developer settings enabled |
| `EXIT: ADB_ENABLED` | App killed due to ADB |
| `EXIT: ROOT_SU_BINARY` | App killed due to root |
| `EXIT: FRIDA_DETECTED` | App killed due to Frida |
| `EXIT: DEBUGGER_TRACER_PID` | App killed due to debugger |
| `PASS: Developer mode check` | Check passed |

---

## 🚨 Common Issues

### Issue 1: "ADB_ENABLED" even after disabling developer mode

**Cause**: The `/dev/socket/adbd` socket persists even after disabling developer mode until the device reboots.

**Solution**: 
```bash
# Option A: Reboot the device
adb reboot

# Option B: Kill ADB daemon (requires root)
adb shell su -c "stop adbd"
```

### Issue 2: Can't find `.sg_debug.txt` on phone

**Cause**: File manager not showing hidden files.

**Solutions**:
1. Files app → ⋮ menu → "Show hidden files"
2. Use **Total Commander** or **Solid Explorer** (better file managers)
3. The dot (.) at the start makes it hidden

### Issue 3: File is empty or doesn't exist

**Cause**: App might not have write permission or exited before writing.

**Solution**: Add storage permission to your app (for debug builds only).

---

## 💡 Alternative: Use On-Device Log Viewer

If you prefer real-time logs:

1. **Install a log viewer app** (before disabling developer mode):
   - **aLogcat** (Free, no root needed)
   - **Logcat Reader** (Free)
   - **MatLog** (Advanced)

2. **Grant log read permission** (one-time setup):
   ```bash
   adb shell pm grant com.dp.logcatapp android.permission.READ_LOGS
   ```

3. **Now you can disable developer mode** and still see logs via the app!

4. **Launch your SecureGuard app**, then immediately switch to the log viewer

5. **Search for these tags**:
   - `MonitorThread`
   - `SecurityCheck`
   - `SocketMonitor`
   - `SystemSettings`
   - `GLThread` (for exit reasons)

---

## 🎯 Quick Test Script

Save this as `test_without_adb.sh`:

```bash
#!/bin/bash

echo "🔨 Building and installing..."
cd /Users/mariganesh/Documents/Projects/SecureGuard/example
flutter build apk --release
adb install -r build/app/outputs/flutter-apk/app-release.apk

echo "🗑️  Clearing old logs..."
adb shell rm /sdcard/Download/.sg_debug.txt

echo "🚀 Launching app..."
adb shell am start -n com.example.example/.MainActivity

echo "⏳ Waiting 5 seconds..."
sleep 5

echo "📥 Pulling logs..."
adb pull /sdcard/Download/.sg_debug.txt ~/Desktop/ 2>/dev/null

if [ -f ~/Desktop/.sg_debug.txt ]; then
    echo "✅ Logs captured:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    cat ~/Desktop/.sg_debug.txt
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
else
    echo "⚠️  No log file found (app might not have exited)"
fi

echo ""
echo "Now you can:"
echo "1. Disable developer mode"
echo "2. Launch the app manually"
echo "3. Check /sdcard/Download/.sg_debug.txt on your phone"
```

Run it:
```bash
chmod +x test_without_adb.sh
./test_without_adb.sh
```

---

## 🔐 Security Note

**IMPORTANT**: The debug log file (`.sg_debug.txt`) should be **REMOVED** in production builds!

To disable debug logging for production:
1. Comment out the `write_debug_log()` calls
2. Or use a build flag to conditionally disable it

This is only for YOUR testing, not for release builds!

---

## 📞 Need Help?

If the app exits and you can't figure out why:

1. Check the debug log file first
2. Use an on-device log viewer app
3. Temporarily re-enable developer mode to use `adb logcat`
4. Check if it's the ADB socket issue (reboot device)

The most common issue is **ADB socket persisting** even after disabling developer mode!
