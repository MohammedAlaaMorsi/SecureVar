package io.mohammedalaamorsi.securevar.security

import java.security.MessageDigest
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Framework-agnostic certificate pinning helper for SecureVar.
 *
 * Validates that the server certificate for WriteKey endpoints matches
 * a set of pinned SHA-256 fingerprints. This mitigates server compromise
 * via MITM attacks, rogue CAs, and DNS hijacking.
 *
 * The helper is designed to work with any HTTP client — it provides:
 * 1. A pinning-aware [javax.net.ssl.SSLSocketFactory] for `HttpsURLConnection`
 * 2. Pin validation utilities usable with OkHttp, Ktor, Volley, etc.
 * 3. Support for backup pins to allow certificate rotation without app updates.
 *
 * ## Usage with HttpsURLConnection
 * ```kotlin
 * val pinConfig = CertificatePinning.PinConfig(
 *     hostname = "api.example.com",
 *     sha256Pins = setOf("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
 *     backupPins = setOf("sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
 * )
 * val connection = URL("https://api.example.com/writekey").openConnection() as HttpsURLConnection
 * CertificatePinning.apply(connection, pinConfig)
 * ```
 *
 * ## Usage with OkHttp
 * ```kotlin
 * val pins = CertificatePinning.PinConfig(
 *     hostname = "api.example.com",
 *     sha256Pins = setOf("sha256/AAAA...=")
 * )
 * val okPinner = okhttp3.CertificatePinner.Builder()
 *     .add(pins.hostname, *pins.allPins.toTypedArray())
 *     .build()
 * val client = OkHttpClient.Builder().certificatePinner(okPinner).build()
 * ```
 *
 * ## Key Rotation
 * Always include **backup pins** so that you can rotate certificates without
 * breaking existing app installs. The backup pin should be the hash of your
 * **next** certificate's public key.
 */
object CertificatePinning {

    /**
     * Pin configuration for a single hostname.
     *
     * @param hostname      The hostname to pin (e.g., "api.example.com")
     * @param sha256Pins    Primary SHA-256 public key hashes (Base64, prefixed with "sha256/")
     * @param backupPins    Backup pins for certificate rotation
     * @param includeSubdomains If true, pins apply to *.hostname as well
     */
    data class PinConfig(
        val hostname: String,
        val sha256Pins: Set<String>,
        val backupPins: Set<String> = emptySet(),
        val includeSubdomains: Boolean = false
    ) {
        /** All pins (primary + backup) for use with OkHttp CertificatePinner. */
        val allPins: Set<String> get() = sha256Pins + backupPins
    }

    /**
     * Apply certificate pinning to an [HttpsURLConnection].
     * This sets a custom SSLSocketFactory + HostnameVerifier that validates
     * the server's certificate against the pinned hashes.
     *
     * @throws SecurityException if the server certificate does not match any pin.
     */
    fun apply(connection: HttpsURLConnection, config: PinConfig) {
        val pinningTrustManager = PinningTrustManager(config)
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf<TrustManager>(pinningTrustManager), null)
        connection.sslSocketFactory = sslContext.socketFactory
        connection.hostnameVerifier = javax.net.ssl.HostnameVerifier { hostname: String, _: javax.net.ssl.SSLSession ->
            if (config.includeSubdomains) {
                hostname == config.hostname || hostname.endsWith(".${config.hostname}")
            } else {
                hostname == config.hostname
            }
        }
    }

    /**
     * Validate a certificate chain against pinned hashes.
     * Useful for custom HTTP client integrations.
     *
     * @return true if at least one certificate in the chain matches a pin.
     */
    fun validateChain(chain: Array<X509Certificate>, config: PinConfig): Boolean {
        val allPins = config.sha256Pins + config.backupPins
        return chain.any { cert ->
            val hash = hashCertificatePublicKey(cert)
            allPins.any { pin ->
                val pinHash = pin.removePrefix("sha256/")
                pinHash == hash
            }
        }
    }

    /**
     * Compute SHA-256 hash of a certificate's SubjectPublicKeyInfo (SPKI).
     * Returns Base64-encoded hash (same format used by HPKP and OkHttp).
     */
    fun hashCertificatePublicKey(cert: X509Certificate): String {
        val spki = cert.publicKey.encoded
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(spki)
        return android.util.Base64.encodeToString(hash, android.util.Base64.NO_WRAP)
    }

    /**
     * Helper to compute the pin string for a certificate.
     * Use this during development to discover the pin for your server's certificate.
     *
     * @return Pin string in "sha256/..." format.
     */
    fun computePin(cert: X509Certificate): String {
        return "sha256/${hashCertificatePublicKey(cert)}"
    }

    // ── Internal TrustManager ───────────────────────────────────────────

    private class PinningTrustManager(
        private val config: PinConfig
    ) : X509TrustManager {

        private val defaultTrustManager: X509TrustManager by lazy {
            val tmf = javax.net.ssl.TrustManagerFactory.getInstance(
                javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm()
            )
            tmf.init(null as java.security.KeyStore?)
            tmf.trustManagers.first { it is X509TrustManager } as X509TrustManager
        }

        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            defaultTrustManager.checkClientTrusted(chain, authType)
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            // First, perform standard certificate validation
            defaultTrustManager.checkServerTrusted(chain, authType)

            // Then, verify against pinned hashes
            if (!validateChain(chain, config)) {
                throw SecurityException(
                    "Certificate pinning failure: server certificate does not match " +
                    "any pinned hash for ${config.hostname}. " +
                    "Expected one of: ${config.allPins.joinToString(", ")}"
                )
            }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return defaultTrustManager.acceptedIssuers
        }
    }
}
