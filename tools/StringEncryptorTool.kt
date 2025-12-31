#!/usr/bin/env kotlin

/**
 * Build-time String Encryption Tool
 * 
 * Usage: kotlinc -script StringEncryptorTool.kt "your-string-here"
 * 
 * This tool generates encrypted versions of strings that can be used
 * in the StringObfuscator class to hide sensitive data from JADX/Ghidra
 */

import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object EncryptionTool {
    
    // Must match the keys in StringObfuscator.kt
    private val k1 = byteArrayOf(0x53.toByte(), 0x65.toByte(), 0x63.toByte(), 0x75.toByte(), 
                                  0x72.toByte(), 0x65.toByte(), 0x47.toByte(), 0x75.toByte())
    private val k2 = byteArrayOf(0x61.toByte(), 0x72.toByte(), 0x64.toByte(), 0x5F.toByte(), 
                                  0x4B.toByte(), 0x65.toByte(), 0x79.toByte(), 0x21.toByte())
    private val k3 = byteArrayOf(0x40.toByte(), 0x32.toByte(), 0x30.toByte(), 0x32.toByte(), 
                                  0x35.toByte(), 0x5F.toByte(), 0x76.toByte(), 0x31.toByte())
    
    private val iv1 = byteArrayOf(0x12.toByte(), 0x34.toByte(), 0x56.toByte(), 0x78.toByte(),
                                   0x9A.toByte(), 0xBC.toByte(), 0xDE.toByte(), 0xF0.toByte())
    private val iv2 = byteArrayOf(0x11.toByte(), 0x22.toByte(), 0x33.toByte(), 0x44.toByte(),
                                   0x55.toByte(), 0x66.toByte(), 0x77.toByte(), 0x88.toByte())
    
    private fun deriveKey(): ByteArray {
        val combined = k1 + k2 + k3
        val md = MessageDigest.getInstance("SHA-256")
        val hash = md.digest(combined)
        return hash.copyOf(16) // AES-128 key
    }
    
    private fun deriveIV(): ByteArray {
        return iv1 + iv2
    }
    
    fun encrypt(plain: String): String {
        return try {
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            val keySpec = SecretKeySpec(deriveKey(), "AES")
            val ivSpec = IvParameterSpec(deriveIV())
            
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
            val encrypted = cipher.doFinal(plain.toByteArray())
            Base64.getEncoder().encodeToString(encrypted).replace("\n", "").trim()
        } catch (e: Exception) {
            println("Error: ${e.message}")
            ""
        }
    }
    
    fun decrypt(encrypted: String): String {
        return try {
            val encryptedBytes = Base64.getDecoder().decode(encrypted)
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            val keySpec = SecretKeySpec(deriveKey(), "AES")
            val ivSpec = IvParameterSpec(deriveIV())
            
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
            val decrypted = cipher.doFinal(encryptedBytes)
            String(decrypted, Charsets.UTF_8)
        } catch (e: Exception) {
            println("Decrypt Error: ${e.message}")
            ""
        }
    }
}

fun main(args: Array<String>) {
    println("====================================")
    println("SecureGuard String Encryption Tool")
    println("====================================\n")
    
    if (args.isEmpty()) {
        println("Usage:")
        println("  Encrypt: kotlinc -script StringEncryptorTool.kt <plaintext>")
        println("  Decrypt: kotlinc -script StringEncryptorTool.kt -d <encrypted>")
        println("\nExamples:")
        println("  kotlinc -script StringEncryptorTool.kt \"/system/bin/su\"")
        println("  kotlinc -script StringEncryptorTool.kt -d \"YjJ2K3pYQmFHN1hJZXFjVGZjL2VlUT09\"")
        println("\nCommon strings to encrypt:")
        println("  - File paths: /system/bin/su, /data/local/tmp")
        println("  - Package names: com.topjohnwu.magisk")
        println("  - Library names: frida-agent, libfrida.so")
        println("  - System props: ro.debuggable, ro.secure")
        return
    }
    
    if (args[0] == "-d" || args[0] == "--decrypt") {
        if (args.size < 2) {
            println("Error: Please provide encrypted string")
            return
        }
        val encrypted = args[1]
        val decrypted = EncryptionTool.decrypt(encrypted)
        println("Encrypted: $encrypted")
        println("Decrypted: $decrypted\n")
        return
    }
    
    // Encrypt mode
    val plaintext = args.joinToString(" ")
    val encrypted = EncryptionTool.encrypt(plaintext)
    
    println("Plaintext: $plaintext")
    println("Encrypted: $encrypted")
    println("\nKotlin usage:")
    println("  StringObfuscator.d(\"$encrypted\") // $plaintext")
    println("\nMethod function:")
    println("  fun myString() = decrypt(\"$encrypted\") // $plaintext")
    
    // Verify encryption
    val verified = EncryptionTool.decrypt(encrypted)
    if (verified == plaintext) {
        println("\n✅ Encryption verified successfully!")
    } else {
        println("\n❌ Encryption verification failed!")
        println("Expected: $plaintext")
        println("Got: $verified")
    }
    println()
}

// Run main
main(args)
