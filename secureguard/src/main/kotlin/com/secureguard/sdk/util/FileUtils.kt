package com.secureguard.sdk.util

import java.io.File

/**
 * File utility functions for security checks
 */
object FileUtils {
    
    /**
     * Check if file exists and is readable
     */
    fun fileExists(path: String): Boolean {
        return try {
            val file = File(path)
            file.exists() && file.canRead()
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Check if file is executable
     */
    fun isExecutable(path: String): Boolean {
        return try {
            val file = File(path)
            file.exists() && file.canExecute()
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Check if directory is writable
     */
    fun isWritable(path: String): Boolean {
        return try {
            val dir = File(path)
            if (dir.exists() && dir.isDirectory) {
                val testFile = File(dir, ".test_${System.currentTimeMillis()}")
                val result = testFile.createNewFile()
                if (result) {
                    testFile.delete()
                }
                result
            } else {
                false
            }
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Read file content safely
     */
    fun readFile(path: String): String? {
        return try {
            File(path).readText()
        } catch (e: Exception) {
            null
        }
    }
}
