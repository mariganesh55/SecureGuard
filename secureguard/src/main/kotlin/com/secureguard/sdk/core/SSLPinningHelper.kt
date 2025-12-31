package com.secureguard.sdk.core

import android.util.Log
import java.io.IOException
import java.security.MessageDigest
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.*

/**
 * SSL Certificate Pinning
 * Prevents Man-in-the-Middle (MITM) attacks by validating server certificates
 * Critical for banking apps to ensure secure communication
 * 
 * Usage:
 * val pinningHelper = SSLPinningHelper()
 * pinningHelper.addPin("yourapi.com", "sha256/AAAAAAAAAA...")
 * 
 * Then use pinningHelper.sslSocketFactory in your HTTP client
 */
class SSLPinningHelper {
    
    private val TAG = "SSLPinning"
    private val pins = mutableMapOf<String, MutableSet<String>>()
    
    /**
     * Add certificate pin for a hostname
     * @param hostname Domain name (e.g., "api.example.com")
     * @param pin SHA-256 hash of the certificate (format: "sha256/BASE64_HASH")
     */
    fun addPin(hostname: String, pin: String) {
        pins.getOrPut(hostname) { mutableSetOf() }.add(pin)
        Log.d(TAG, "Added pin for $hostname")
    }
    
    /**
     * Add multiple pins for a hostname (for certificate rotation)
     */
    fun addPins(hostname: String, pinList: List<String>) {
        pins.getOrPut(hostname) { mutableSetOf() }.addAll(pinList)
        Log.d(TAG, "Added ${pinList.size} pins for $hostname")
    }
    
    /**
     * Get SSLSocketFactory with certificate pinning
     * Use this in your HTTP client (OkHttp, HttpsURLConnection, etc.)
     */
    val sslSocketFactory: SSLSocketFactory
        get() {
            val trustManager = PinningTrustManager(pins)
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, arrayOf<TrustManager>(trustManager), null)
            return sslContext.socketFactory
        }
    
    /**
     * Get X509TrustManager for certificate pinning
     * Use this with sslSocketFactory in OkHttp
     */
    val trustManager: X509TrustManager
        get() = PinningTrustManager(pins)
    
    /**
     * Calculate SHA-256 pin of a certificate
     * Use this to get pin values for your certificates
     */
    fun calculatePin(certificate: Certificate): String {
        val publicKey = certificate.publicKey.encoded
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(publicKey)
        val base64 = android.util.Base64.encodeToString(hash, android.util.Base64.NO_WRAP)
        return "sha256/$base64"
    }
    
    /**
     * Custom TrustManager that implements certificate pinning
     */
    private class PinningTrustManager(
        private val pins: Map<String, Set<String>>
    ) : X509TrustManager {
        
        private val TAG = "PinningTrustManager"
        private val defaultTrustManager: X509TrustManager
        
        init {
            val trustManagerFactory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm()
            )
            trustManagerFactory.init(null as? java.security.KeyStore)
            
            defaultTrustManager = trustManagerFactory.trustManagers
                .filterIsInstance<X509TrustManager>()
                .first()
        }
        
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            // Not used for client certificate validation
            defaultTrustManager.checkClientTrusted(chain, authType)
        }
        
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            if (chain == null || chain.isEmpty()) {
                throw CertificateException("Certificate chain is empty")
            }
            
            // First, perform standard certificate validation
            defaultTrustManager.checkServerTrusted(chain, authType)
            
            // Then, check pinning if configured
            if (pins.isNotEmpty()) {
                verifyPinning(chain)
            }
        }
        
        /**
         * Verify certificate pinning
         */
        private fun verifyPinning(chain: Array<out X509Certificate>) {
            // Calculate pins for all certificates in chain
            val actualPins = chain.map { certificate ->
                val publicKey = certificate.publicKey.encoded
                val digest = MessageDigest.getInstance("SHA-256")
                val hash = digest.digest(publicKey)
                val base64 = android.util.Base64.encodeToString(hash, android.util.Base64.NO_WRAP)
                "sha256/$base64"
            }.toSet()
            
            Log.d(TAG, "Actual certificate pins: $actualPins")
            
            // Check if any actual pin matches any expected pin
            val pinMatched = pins.values.any { expectedPins ->
                actualPins.intersect(expectedPins).isNotEmpty()
            }
            
            if (!pinMatched && pins.isNotEmpty()) {
                Log.e(TAG, "Certificate pinning failed!")
                Log.e(TAG, "Expected pins: ${pins.values.flatten()}")
                Log.e(TAG, "Actual pins: $actualPins")
                throw CertificateException(
                    "Certificate pinning failed. This may indicate a Man-in-the-Middle attack!"
                )
            }
            
            Log.d(TAG, "Certificate pinning verification successful")
        }
        
        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return defaultTrustManager.acceptedIssuers
        }
    }
    
    companion object {
        /**
         * Create a no-op hostname verifier (use with caution!)
         * Only for development/testing
         */
        fun createAllowAllHostnameVerifier(): HostnameVerifier {
            return HostnameVerifier { _, _ -> true }
        }
        
        /**
         * Extract certificate pins from a URL
         * Use this during development to get pins for your API
         */
        fun extractPinsFromUrl(url: String): List<String> {
            val pins = mutableListOf<String>()
            
            try {
                val connection = java.net.URL(url).openConnection() as HttpsURLConnection
                connection.connect()
                
                val certificates = connection.serverCertificates
                certificates.forEach { certificate ->
                    if (certificate is X509Certificate) {
                        val publicKey = certificate.publicKey.encoded
                        val digest = MessageDigest.getInstance("SHA-256")
                        val hash = digest.digest(publicKey)
                        val base64 = android.util.Base64.encodeToString(hash, android.util.Base64.NO_WRAP)
                        val pin = "sha256/$base64"
                        pins.add(pin)
                        
                        Log.d("SSLPinning", "Certificate subject: ${certificate.subjectDN}")
                        Log.d("SSLPinning", "Certificate pin: $pin")
                    }
                }
                
                connection.disconnect()
            } catch (e: Exception) {
                Log.e("SSLPinning", "Failed to extract pins from $url", e)
            }
            
            return pins
        }
    }
}

/**
 * Helper extension for OkHttp integration
 */
object SSLPinningOkHttpHelper {
    /**
     * Configure OkHttpClient with SSL pinning
     * 
     * Example:
     * val client = OkHttpClient.Builder()
     *     .apply { configureSslPinning(pinningHelper) }
     *     .build()
     */
    /*
    // OkHttp extension - requires okhttp3 dependency
    fun okhttp3.OkHttpClient.Builder.configureSslPinning(helper: SSLPinningHelper): okhttp3.OkHttpClient.Builder {
        return this.sslSocketFactory(helper.sslSocketFactory, helper.trustManager)
    }
    */
}
