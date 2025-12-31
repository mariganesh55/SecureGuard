#!/usr/bin/env kotlin

/**
 * String Encryption Tool for SecureGuard
 * 
 * This tool helps developers encrypt sensitive strings for use in SecureGuard.
 * Run this script to generate encrypted versions of your sensitive data.
 * 
 * Usage:
 * kotlin StringEncryptor.kt
 * 
 * Or compile and run:
 * kotlinc StringEncryptor.kt -include-runtime -d StringEncryptor.jar
 * java -jar StringEncryptor.jar
 */

import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object StringEncryptor {
    
    // Must match the key in StringObfuscator.kt
    private const val KEY = "SecureGuardKey16" // 16 bytes for AES-128
    private const val IV = "SecureGuardIV16!" // 16 bytes IV
    
    /**
     * Encrypt a plain string using AES-128
     */
    fun encrypt(plain: String): String {
        return try {
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            val keySpec = SecretKeySpec(KEY.toByteArray(), "AES")
            val ivSpec = IvParameterSpec(IV.toByteArray())
            
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
            val encrypted = cipher.doFinal(plain.toByteArray())
            Base64.getEncoder().encodeToString(encrypted)
        } catch (e: Exception) {
            throw RuntimeException("Encryption failed: ${e.message}", e)
        }
    }
    
    /**
     * Decrypt an encrypted string (for verification)
     */
    fun decrypt(encrypted: String): String {
        return try {
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            val keySpec = SecretKeySpec(KEY.toByteArray(), "AES")
            val ivSpec = IvParameterSpec(IV.toByteArray())
            
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
            val decrypted = cipher.doFinal(Base64.getDecoder().decode(encrypted))
            String(decrypted)
        } catch (e: Exception) {
            throw RuntimeException("Decryption failed: ${e.message}", e)
        }
    }
    
    /**
     * Generate Kotlin code for a new obfuscated string method
     */
    fun generateKotlinMethod(methodName: String, plainString: String): String {
        val encrypted = encrypt(plainString)
        return """
    fun $methodName() = decrypt("$encrypted") // $plainString
        """.trimIndent()
    }
    
    /**
     * Encrypt a list of strings and generate Kotlin code
     */
    fun generateMethodsForList(baseName: String, strings: List<String>): String {
        return buildString {
            strings.forEachIndexed { index, str ->
                val methodName = "$baseName${index + 1}"
                appendLine(generateKotlinMethod(methodName, str))
            }
            appendLine()
            appendLine("    fun getAll${baseName.replaceFirstChar { it.uppercase() }}s(): Array<String> = arrayOf(")
            strings.indices.forEach { index ->
                val suffix = if (index < strings.size - 1) "," else ""
                appendLine("        $baseName${index + 1}()$suffix")
            }
            appendLine("    )")
        }
    }
}

fun main() {
    println("=".repeat(60))
    println("SecureGuard String Encryption Tool")
    println("=".repeat(60))
    println()
    
    // Example 1: Encrypt individual strings
    println("Example 1: Individual String Encryption")
    println("-".repeat(60))
    
    val examples = listOf(
        "/system/bin/su",
        "com.topjohnwu.magisk",
        "de.robv.android.xposed.installer"
    )
    
    examples.forEach { plain ->
        val encrypted = StringEncryptor.encrypt(plain)
        val decrypted = StringEncryptor.decrypt(encrypted)
        println("Plain:     $plain")
        println("Encrypted: $encrypted")
        println("Decrypted: $decrypted")
        println("Match:     ${plain == decrypted}")
        println()
    }
    
    // Example 2: Generate Kotlin methods
    println("\nExample 2: Generate Kotlin Method")
    println("-".repeat(60))
    println(StringEncryptor.generateKotlinMethod("customPath", "/data/custom/path"))
    
    // Example 3: Generate methods for a list
    println("\nExample 3: Generate Multiple Methods")
    println("-".repeat(60))
    val customPaths = listOf(
        "/system/custom/path1",
        "/system/custom/path2",
        "/data/custom/file"
    )
    println(StringEncryptor.generateMethodsForList("customPath", customPaths))
    
    // Interactive mode
    println("\n" + "=".repeat(60))
    println("Interactive Mode")
    println("=".repeat(60))
    println("Enter strings to encrypt (one per line, empty line to exit):")
    
    while (true) {
        print("> ")
        val input = readLine()?.trim() ?: break
        
        if (input.isEmpty()) {
            break
        }
        
        try {
            val encrypted = StringEncryptor.encrypt(input)
            println("Encrypted: $encrypted")
            println("Method:    fun str() = decrypt(\"$encrypted\") // $input")
        } catch (e: Exception) {
            println("Error: ${e.message}")
        }
        println()
    }
    
    println("\nExiting...")
}

// Run the main function if executed as script
main()
