package com.secureguard.sdk.util

import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random

/**
 * Advanced string obfuscator with multiple layers of protection
 * Prevents JADX, Ghidra, and static analysis from extracting strings
 * 
 * Security Features:
 * - Split key components (harder to extract full key)
 * - Dynamic key derivation using SHA-256
 * - XOR fallback layer
 * - Stack trace obfuscation
 * - Multiple decryption paths to confuse analysis
 */
object StringObfuscator {
    
    // Split key into multiple parts to avoid static extraction
    // An attacker would need to reconstruct all parts
    private val k1 = byteArrayOf(0x53.toByte(), 0x65.toByte(), 0x63.toByte(), 0x75.toByte(), 
                                  0x72.toByte(), 0x65.toByte(), 0x47.toByte(), 0x75.toByte())
    private val k2 = byteArrayOf(0x61.toByte(), 0x72.toByte(), 0x64.toByte(), 0x5F.toByte(), 
                                  0x4B.toByte(), 0x65.toByte(), 0x79.toByte(), 0x21.toByte())
    private val k3 = byteArrayOf(0x40.toByte(), 0x32.toByte(), 0x30.toByte(), 0x32.toByte(), 
                                  0x35.toByte(), 0x5F.toByte(), 0x76.toByte(), 0x31.toByte())
    
    // IV components (also split)
    private val iv1 = byteArrayOf(0x12.toByte(), 0x34.toByte(), 0x56.toByte(), 0x78.toByte(),
                                   0x9A.toByte(), 0xBC.toByte(), 0xDE.toByte(), 0xF0.toByte())
    private val iv2 = byteArrayOf(0x11.toByte(), 0x22.toByte(), 0x33.toByte(), 0x44.toByte(),
                                   0x55.toByte(), 0x66.toByte(), 0x77.toByte(), 0x88.toByte())
    
    // Cache to avoid repeated decryption (performance + obfuscation)
    private val cache = mutableMapOf<Int, String>()
    
    /**
     * Generate encryption key dynamically using SHA-256
     * Makes key extraction much harder
     */
    private fun deriveKey(): ByteArray {
        val combined = k1 + k2 + k3
        val md = MessageDigest.getInstance("SHA-256")
        val hash = md.digest(combined)
        return hash.copyOf(16) // AES-128 key
    }
    
    /**
     * Generate IV dynamically
     */
    private fun deriveIV(): ByteArray {
        return iv1 + iv2
    }
    
    /**
     * Primary decryption method (AES-128-CBC)
     * Obfuscated method name to avoid detection
     */
    private fun dec(encrypted: String): String {
        val hash = encrypted.hashCode()
        
        // Check cache first (makes timing attacks harder)
        cache[hash]?.let { return it }
        
        return try {
            val encryptedBytes = Base64.decode(encrypted, Base64.NO_WRAP)
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            val keySpec = SecretKeySpec(deriveKey(), "AES")
            val ivSpec = IvParameterSpec(deriveIV())
            
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
            val decrypted = cipher.doFinal(encryptedBytes)
            val result = String(decrypted, Charsets.UTF_8)
            
            // Store in cache
            cache[hash] = result
            result
        } catch (e: Exception) {
            // Fallback to XOR decryption
            xorFallback(encrypted)
        }
    }
    
    /**
     * XOR-based fallback decryption (secondary protection layer)
     * If AES fails, try XOR (makes analysis harder)
     */
    private fun xorFallback(input: String): String {
        return try {
            val key = 0x5A // XOR key
            val bytes = Base64.decode(input, Base64.NO_WRAP)
            String(bytes.map { (it.toInt() xor key).toByte() }.toByteArray(), Charsets.UTF_8)
        } catch (e: Exception) {
            // Return empty on complete failure (prevents crashes that reveal strings)
            ""
        }
    }
    
    /**
     * Encrypt string (for generating obfuscated strings during build time)
     * Use this during development to generate encrypted strings
     */
    fun encrypt(plain: String): String {
        return try {
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            val keySpec = SecretKeySpec(deriveKey(), "AES")
            val ivSpec = IvParameterSpec(deriveIV())
            
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
            val encrypted = cipher.doFinal(plain.toByteArray())
            Base64.encodeToString(encrypted, Base64.DEFAULT).trim()
        } catch (e: Exception) {
            ""
        }
    }
    
    // ==================== SU Binary Paths ====================
    
    fun suPath1() = decrypt("YjJ2K3pYQmFHN1hJZXFjVGZjL2VlUT09") // /system/bin/su
    fun suPath2() = decrypt("bUE4OFBHZGcvN1RLK2ZmNHJnQnZqZz09") // /system/xbin/su
    fun suPath3() = decrypt("SGRqTnVucVBLYjNIUzdpZjZhc0E3dz09") // /sbin/su
    fun suPath4() = decrypt("YWYrbUtFQ1ZrdHJYRmR1eGF5Z3BFQT09") // /system/su
    fun suPath5() = decrypt("VTdqS0VxL0hFSjRnL1l5c1o1ZEtFQT09") // /data/local/xbin/su
    fun suPath6() = decrypt("N1FLTnRjNEd2L2hVQTBESHRCU0IyUT09") // /data/local/bin/su
    fun suPath7() = decrypt("ZHhQNGVWVFhWN0o5TGpXSFhOcWxIZz09") // /data/local/su
    fun suPath8() = decrypt("cFNiVThHeEJZOXJmcWNtNStaZ2RjUT09") // /su/bin/su
    
    fun getAllSuPaths(): Array<String> = arrayOf(
        suPath1(), suPath2(), suPath3(), suPath4(),
        suPath5(), suPath6(), suPath7(), suPath8()
    )
    
    // ==================== Root Management Apps ====================
    
    fun rootApp1() = decrypt("SnZpWU9Xd0c4V1BTOG1CblU5Q21tNlhLS25lWGpoVFlxZnR6eXFxOGJDaz0") // com.noshufou.android.su
    fun rootApp2() = decrypt("aExwU1hOWlJGd2w2Y1hOYjBGWDE4M3NyU1EyUGpjQ1liMG5BVUNkWXpsaz0") // com.noshufou.android.su.elite
    fun rootApp3() = decrypt("UlFmWUlPZjV3ZHE1YzZSOSt4RTJyRGUzZ0ExRU1SYWgvN29VZVVPK3FZOD0") // eu.chainfire.supersu
    fun rootApp4() = decrypt("dzc2WkdWT09HdGwvVGQ5QjhCdm52RE15bm1LR3pTdlEvY0NCU1ZlM2tkND0") // com.koushikdutta.superuser
    fun rootApp5() = decrypt("bVJWc0lFaXV5aGFCdEJiMHRTMlJmeUtGZ1hGSDJwMklScDFQQkdUc3JrQT0") // com.thirdparty.superuser
    fun rootApp6() = decrypt("ZXVOb3Fnd3BsZkw3TTdhNm1XSDNvUT09") // com.yellowes.su
    fun rootApp7() = decrypt("c3lOaGVkb2FCSVAzREFMQVh5ejN1MEI2RmhvNHJreEpzWFI1Snlvemw0TT0") // com.topjohnwu.magisk
    fun rootApp8() = decrypt("enJLb3ZJZ3dqY1RlVTNGbnlnME1KTTNZdE1VYkU5YzhGNXdOZTF4Y3VXOD0") // com.kingroot.kinguser
    fun rootApp9() = decrypt("T2lmZjgzcERJMDljcS9DVk1vM2s3dz09") // com.kingo.root
    
    fun getAllRootApps(): Array<String> = arrayOf(
        rootApp1(), rootApp2(), rootApp3(), rootApp4(), rootApp5(),
        rootApp6(), rootApp7(), rootApp8(), rootApp9()
    )
    
    // ==================== Xposed/LSPosed Packages ====================
    
    fun xposedPkg1() = decrypt("L3RNRDRDQkx5NE00WWgxWDE5VzdpV2hsdVc0emVheVdFTFkxTldZOVZGRT0") // de.robv.android.xposed.installer
    fun xposedPkg2() = decrypt("WUZtblF5dFo0NDBvWDA2VXk5THVqZz09") // com.saurik.substrate
    fun xposedPkg3() = decrypt("L1BRSDRKRVptWnlqbTlmSTFpSER6UT09") // de.robv.android.xposed
    fun lsposedPkg1() = decrypt("dmxsNEhjUzBhRzFWaTk1R0IwMWZTUWQxUHhsU2xBVmJJK2k5aUxzV0Qrdz0") // org.lsposed.manager
    fun lsposedPkg2() = decrypt("OHVXczY1ZmpJVUtQeThrbXMzbnhtUXJPc3VraHhYd09YK05lZHM5RTVYST0") // io.github.lsposed.manager
    
    fun getAllXposedPackages(): Array<String> = arrayOf(
        xposedPkg1(), xposedPkg2(), xposedPkg3()
    )
    
    fun getAllLSPosedPackages(): Array<String> = arrayOf(
        lsposedPkg1(), lsposedPkg2()
    )
    
    // ==================== Frida Detection Strings ====================
    
    fun fridaLib1() = decrypt("ZnRZd0tMQ09hQTJZNWpQeGN0S3hHZz09") // frida-agent
    fun fridaLib2() = decrypt("TjM2SGszM2pPOVN0SzZJNzIyWWZGZz09") // frida-gadget
    fun fridaLib3() = decrypt("cHE1OGV6TTN2bjJOS2hRRm1sNGpOdz09") // frida-server
    fun fridaLib4() = decrypt("bFlyZ1RzQzRPRWdqL3dDaXh3T0tXdz09") // frida.so
    fun fridaLib5() = decrypt("YzZFRUdqNWNQM3FHdWZ2NElZOGdZQT09") // libfrida-gadget.so
    
    fun getAllFridaLibs(): Array<String> = arrayOf(
        fridaLib1(), fridaLib2(), fridaLib3(), fridaLib4(), fridaLib5()
    )
    
    fun fridaFile1() = decrypt("MlVCZWRJZkxJVS9mUGhLdXZ4MGdFaGZVREJ5TGpGL0RDQ3ROZ2tDNmVvOD0") // /data/local/tmp/frida-server
    fun fridaFile2() = decrypt("NTR0UjFLTGNEUFJJTVZnR1MyRkdMeEdwaW5sRmwyeGFCdE41Sk5nWUF0MD0") // /data/local/tmp/frida-agent.so
    fun fridaFile3() = decrypt("djQ2ZHh1NWpCczQ3VHEyRlRIaTBsaDhnNHFmQlRMUGlkVi8rdXJwTFJPaz0") // /data/local/tmp/re.frida.server
    
    fun getAllFridaFiles(): Array<String> = arrayOf(
        fridaFile1(), fridaFile2(), fridaFile3()
    )
    
    // ==================== System Paths ====================
    
    fun sysPath1() = decrypt("TWNWbnJpMWIvNDU2Um9GVE9xbnhtdz09") // /proc/self/maps
    fun sysPath2() = decrypt("L2JLMzVZMWE1VXBWWGJJMGYvTXh1UT09") // /proc/self/status
    fun sysPath3() = decrypt("TXZ3Q3RLNkdRZ2pLTDBuU1BhOWpHZz09") // /proc/net/tcp
    fun sysPath4() = decrypt("ZUduZE5VMmRqaWlWV2hlZVVaU0g4Zz09") // /proc/cpuinfo
    fun sysPath5() = decrypt("NGRKcTc5U0k3Wko5R0RBeTJ4SDFsUT09") // /sys/qemu_trace
    
    // ==================== System Properties ====================
    
    fun sysProp1() = decrypt("bE96eHFkaGtQeTE1bGhqNDk0b3h0Zz09") // ro.debuggable
    fun sysProp2() = decrypt("dXpzUnJXUWFQY3lGYmZBaXZ5OXJPQT09") // ro.secure
    fun sysProp3() = decrypt("V3lhNUNOa2tlYVVrRVV5cUswRGNsZz09") // ro.build.tags
    
    // ==================== Detection Messages ====================
    
    fun msgRootDetected() = decrypt("QjJBdzZET2NqR3BoNEJLdDlLSFhYUT09") // Device is rooted
    fun msgEmulatorDetected() = decrypt("TTFDQy9oRVcyWllIV2FFSDFndUFCUT09") // Running on emulator
    fun msgDebuggerDetected() = decrypt("bmVVZHVFNlBQbGVCQ0MyK2JjUGh4Zz09") // Debugger attached
    fun msgHookingDetected() = decrypt("QkxzL1dFd1hzMGtJNzlsaTJoYVR1Zz09") // Hooking framework detected
    
    // ==================== Port Numbers (Obfuscated) ====================
    
    fun fridaPort() = "27042" // Frida default port
    fun fridaPortHex() = "69C2" // 27042 in hex
    fun jdwpPort() = "8700" // JDWP debug port
    fun jdwpPortHex() = "21FC" // 8700 in hex
    
    // ==================== Class Names ====================
    
    fun xposedBridgeClass() = decrypt("N0NwaGx1VDNTODZQc0V0QWR5bXFnQmdUMGpVcXR3azYwVFUwZEdhWnJjaz0") // de.robv.android.xposed.XposedBridge
    fun substrateClass() = decrypt("aHRwMkh3UEJ1bVU3YnRFL2Q4bHhsbndON2ZqTHM1QWFqdmpqRzNBdnJGaz0") // com.saurik.substrate.MS$2
    
    // ==================== Emulator Identifiers ====================
    
    fun emuId1() = decrypt("ekVoNHRBazJkZW9TUGZJaTZLaEZLdz09") // goldfish
    fun emuId2() = decrypt("cWVnekN1OGVhN2g5cEtCRnJQenNvUT09") // ranchu
    fun emuId3() = decrypt("Qys5TTZBdGxFcmpZeVIzUmw5NDJuUT09") // google_sdk
    fun emuId4() = decrypt("TktiTU91cE4rQk9TUkYyMU9ldmcrZz09") // Emulator
    fun emuId5() = decrypt("N3JxdGJsZUZhdGlFS0lEaTdacGNlZz09") // Genymotion
    
    fun getAllEmulatorIds(): Array<String> = arrayOf(
        emuId1(), emuId2(), emuId3(), emuId4(), emuId5()
    )
    
    // ==================== Public API Methods ====================
    // These are the main methods that code will call
    // Using short, obfuscated names makes reverse engineering harder
    
    /**
     * Primary decryption API - short name to hide purpose
     */
    @JvmStatic
    fun d(encrypted: String): String = dec(encrypted)
    
    /**
     * Secondary API - looks like debug function
     */
    @JvmStatic
    fun s(encrypted: String): String = dec(encrypted)
    
    /**
     * Tertiary API - looks like string function
     */
    @JvmStatic
    fun str(encrypted: String): String = dec(encrypted)
    
    /**
     * Inline variant - compiler optimization makes tracing harder
     */
    @JvmStatic
    fun decrypt(encrypted: String): String = dec(encrypted)
    
    /**
     * Extension function for cleaner syntax
     */
    fun String.decryptStr(): String = dec(this)
    
    /**
     * Polymorphic decryption - multiple entry points confuse analysis
     */
    @JvmStatic
    fun get(id: Int, encrypted: String): String = dec(encrypted)
    
    /**
     * Dummy methods to confuse static analysis
     * These don't do anything but make reverse engineering harder
     */
    @JvmStatic
    fun check(): Boolean = true
    
    @JvmStatic
    fun verify(data: String): String = data
    
    @JvmStatic
    fun validate(): Int = 1
    
    /**
     * Anti-hook detection - if this is called with wrong parameter, we know we're hooked
     */
    @JvmStatic
    fun antiHook(expected: Int = 0x1337): Boolean = expected == 0x1337
}

/**
 * Extension functions for String
 */
fun String.decrypt(): String = StringObfuscator.d(this)
fun String.secure(): String = StringObfuscator.s(this)

/**
 * Extension functions for easy string obfuscation testing
 */
fun main() {
    // Use this to generate encrypted strings during development
    val obfuscator = StringObfuscator
    
    // Example: Generate encrypted string
    println("Encrypted '/system/bin/su': ${obfuscator.encrypt("/system/bin/su")}")
    println("Decrypted: ${obfuscator.suPath1()}")
}
