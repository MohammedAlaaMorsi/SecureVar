package io.mohammedalaamorsi.trckqapp.security

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import io.mohammedalaamorsi.trckq.WriteKey
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.runBlocking

private val Context.nonceDataStore by preferencesDataStore(name = "write_key_secure_store")

/**
 * WriteKeyValidator - Demonstrates advanced WriteKey validation features
 * 
 * This class shows how to use the enhanced WriteKey system in production
 */
object WriteKeyValidator {
    /**
     * ValidationResult - Structured outcomes for key validation
     */
    sealed class ValidationResult {
        object Valid : ValidationResult()
        data class InvalidFormat(val reason: String) : ValidationResult()
        data class Expired(val ageMillis: Long) : ValidationResult()
        data class Replay(val nonce: String) : ValidationResult()
        data class SignatureMismatch(val expected: String?, val actual: String?) : ValidationResult()
        data class ClockSkewExceeded(val skewMillis: Long) : ValidationResult()
        data class AsymSignatureMismatch(val reason: String) : ValidationResult()
        object NonceStoreTampered : ValidationResult()
    }

    // Configurable tolerances
    private const val MAX_CLOCK_SKEW_MILLIS = 10_000L // 10s tolerance for device/server skew (default)
    private const val MAX_NONCE_HISTORY = 2000 // increase capacity vs library default

    // In production, injected from secure source (backend provisioned secret per install or dynamic) - DO NOT hardcode.
    private const val APP_SECRET_KEY = "your-app-secret-key-from-backend" // placeholder
    // Public key for asymmetric verification (X.509 SubjectPublicKeyInfo DER, Base64). Provide via secure config.
    private const val PUBLIC_KEY_B64: String = "" // fallback if dynamic not set
    @Volatile private var publicKeyBase64: String? = null
    @Volatile private var testHighRiskOverride: Boolean? = null // TEST ONLY override of risk posture
    // Integrity MAC secret for nonce persistence (placeholder; provision securely)
    private const val NONCE_INTEGRITY_SECRET = "nonce-integrity-secret"
    private const val NONCE_MAC_KEY = "nonce_store_mac"

    /** Configure the asymmetric public key at runtime (Base64 X.509 SubjectPublicKeyInfo). */
    fun configurePublicKey(base64: String) {
        publicKeyBase64 = base64.trim()
    }

    /**
     * TEST-ONLY: Corrupt nonce store MAC to simulate tampering.
     * Do not call in production.
     */
    fun testCorruptNonceStoreMac(context: Context) = runBlocking {
        val macKey = stringPreferencesKey(NONCE_MAC_KEY)
        context.nonceDataStore.edit { it[macKey] = "corrupt" }
    }

    /**
     * TEST-ONLY: Force high risk posture (null to clear).
     */
    fun testForceHighRisk(flag: Boolean?) { testHighRiskOverride = flag }

    /**
     * TEST-ONLY: Reset nonce store and integrity MAC.
     */
    fun testResetNonceStore(context: Context) = runBlocking {
        context.nonceDataStore.edit { preferences ->
            preferences.asMap().keys.filter {
                it.name.startsWith("nonce_") || it.name == NONCE_MAC_KEY
            }.forEach { key ->
                @Suppress("UNCHECKED_CAST")
                preferences.remove(key as androidx.datastore.preferences.core.Preferences.Key<Any>)
            }
        }
    }

    // SharedPreferences for nonce persistence (survives process restarts)
    private fun prefs(context: Context): android.content.SharedPreferences {
        return context.getSharedPreferences("write_key_secure_store", Context.MODE_PRIVATE)
    }

    /**
     * Validate a WriteKey received from backend.
     * Performs format, expiry, replay, signature, and clock skew checks.
     * NOTE: This does NOT mark the nonce as used—call markNonceUsed() after successful write.
     */
    fun validate(writeKey: WriteKey, context: Context): ValidationResult {
        val now = System.currentTimeMillis()
        val age = now - writeKey.timestamp
        val risk = assessRisk(context)
        val allowedSkew = if (risk.highRisk) 1_000L else MAX_CLOCK_SKEW_MILLIS

        // 1. Format check
        if (writeKey.nonce.isBlank()) {
            return ValidationResult.InvalidFormat("Empty nonce")
        }
        if (!writeKey.nonce.matches(Regex("^[0-9a-fA-F]{16,64}$"))) { // hex length check
            return ValidationResult.InvalidFormat("Nonce not hex or length out of range")
        }

        // 2. Clock skew tolerance (future timestamps beyond tolerance are suspicious)
        if (writeKey.timestamp - now > allowedSkew) {
            return ValidationResult.ClockSkewExceeded(writeKey.timestamp - now)
        }

        // 3. Expiry check
        if (writeKey.isExpired()) {
            return ValidationResult.Expired(age)
        }

        // 4. Replay & integrity check via persistent store
        val prefs = prefs(context)
        // Verify integrity MAC over nonce set before trusting contents
        if (!verifyNonceStoreMac(prefs)) {
            return ValidationResult.NonceStoreTampered
        }
        val usedKey = "nonce_${writeKey.nonce}" // key per nonce
        
        // Allow nonce reuse within a short window (5s) for scope-bound batch writes (e.g., login with multiple properties)
        if (prefs.contains(usedKey)) {
            val firstUsed = prefs.getLong(usedKey, 0L)
            val elapsedSinceFirstUse = now - firstUsed
            // If nonce was used recently (within 5s) AND has same scope, allow reuse for batch
            if (elapsedSinceFirstUse < 5_000L) {
                // Allow reuse within grace period for same scope
                val storedScope = prefs.getString("${usedKey}_scope", null)
                if (storedScope == writeKey.scope) {
                    // Same scope, within grace period—allow
                } else {
                    // Different scope or no scope match—reject
                    return ValidationResult.Replay(writeKey.nonce)
                }
            } else {
                // Grace period expired—reject
                return ValidationResult.Replay(writeKey.nonce)
            }
        }

        // 5. Signature verification (prefer asymmetric; fallback to HMAC; mandatory if high-risk)
        val asymSig = writeKey.asymSignature
        if (asymSig != null) {
            val ok = verifyAsymmetric(
                nonce = writeKey.nonce,
                timestamp = writeKey.timestamp,
                userId = writeKey.userId,
                propertyName = writeKey.propertyName,
                scope = writeKey.scope,
                signatureB64 = asymSig
            )
            if (!ok) return ValidationResult.AsymSignatureMismatch("Asymmetric signature verification failed")
        } else if (writeKey.signature != null) {
            val expected = computeSignature(
                nonce = writeKey.nonce,
                timestamp = writeKey.timestamp,
                secretKey = APP_SECRET_KEY,
                userId = writeKey.userId,
                propertyName = writeKey.propertyName,
                scope = writeKey.scope
            )
            if (!constantTimeEquals(expected, writeKey.signature)) {
                return ValidationResult.SignatureMismatch(expected, writeKey.signature)
            }
        } else if (risk.highRisk) {
            return ValidationResult.InvalidFormat("Missing signature under high-risk posture")
        }

        // DO NOT mark nonce as used here—validation is read-only.
        // Caller must call markNonceUsed() after successful write.
        return ValidationResult.Valid
    }

    /**
     * Mark a nonce as used after successful write.
     * Call this ONLY after the write has been applied.
     */
    fun markNonceUsed(writeKey: WriteKey, context: Context) {
        val prefs = prefs(context)
        val usedKey = "nonce_${writeKey.nonce}"
        val now = System.currentTimeMillis()
        
        // If not already marked, mark with timestamp and scope
        if (!prefs.contains(usedKey)) {
            prefs.edit { 
                putLong(usedKey, now)
                putString("${usedKey}_scope", writeKey.scope ?: "-")
            }
            updateNonceStoreMac(prefs)
            pruneNonceHistoryIfNeeded(prefs)
        }
        // If already marked (scope-bound batch), do nothing—grace period allows reuse
    }

    /** Generate a test key (simulating backend) */
    fun generateTestKey(ttlSeconds: Int = 300): WriteKey {
        return WriteKey.generate(
            secretKey = APP_SECRET_KEY,
            ttlMillis = TimeUnit.SECONDS.toMillis(ttlSeconds.toLong())
        )
    }

    /** Construct WriteKey from server payload */
    fun fromServerResponse(
        nonce: String,
        timestamp: Long = System.currentTimeMillis(),
        signature: String? = null,
        ttlSeconds: Int = 300,
        userId: String? = null,
        scope: String? = null,
        propertyName: String? = null,
        asymSignature: String? = null
    ): WriteKey = WriteKey(
        nonce = nonce,
        timestamp = timestamp,
        signature = signature,
        ttlMillis = TimeUnit.SECONDS.toMillis(ttlSeconds.toLong()),
        userId = userId,
        propertyName = propertyName,
        scope = scope,
        asymSignature = asymSignature
    )

    /** Constant-time comparison to mitigate timing attacks */
    private fun constantTimeEquals(expected: String?, actual: String?): Boolean {
        if (expected == null || actual == null) return expected == actual
        if (expected.length != actual.length) return false
        var result = 0
        for (i in expected.indices) {
            result = result or (expected[i].code xor actual[i].code)
        }
        return result == 0
    }

    /** HMAC-SHA256 signature computation mirroring WriteKey.generateSignature */
    private fun computeSignature(
        nonce: String,
        timestamp: Long,
        secretKey: String,
        userId: String? = null,
        propertyName: String? = null,
        scope: String? = null
    ): String {
        return try {
            val message = buildString {
                append(nonce)
                append(':')
                append(timestamp)
                append(':')
                append(userId ?: "-")
                append(':')
                append(propertyName ?: "-")
                append(':')
                append(scope ?: "-")
            }
            val mac = javax.crypto.Mac.getInstance("HmacSHA256")
            val secretKeySpec = javax.crypto.spec.SecretKeySpec(secretKey.toByteArray(Charsets.UTF_8), "HmacSHA256")
            mac.init(secretKeySpec)
            val hmacBytes = mac.doFinal(message.toByteArray(Charsets.UTF_8))
            android.util.Base64.encodeToString(hmacBytes, android.util.Base64.NO_WRAP)
        } catch (e: Exception) {
            // Fallback: SHA-256
            try {
                val digest = MessageDigest.getInstance("SHA-256")
                val fallbackMsg = buildString {
                    append(nonce)
                    append(':')
                    append(timestamp)
                    append(':')
                    append(userId ?: "-")
                    append(':')
                    append(propertyName ?: "-")
                    append(':')
                    append(scope ?: "-")
                    append(':')
                    append(secretKey)
                }
                val hashBytes = digest.digest(fallbackMsg.toByteArray(Charsets.UTF_8))
                android.util.Base64.encodeToString(hashBytes, android.util.Base64.NO_WRAP)
            } catch (e2: Exception) {
                buildString {
                    append(nonce)
                    append(':')
                    append(timestamp)
                    append(':')
                    append(userId ?: "-")
                    append(':')
                    append(propertyName ?: "-")
                    append(':')
                    append(scope ?: "-")
                    append(':')
                    append(secretKey)
                }.hashCode().toString(16)
            }
        }
    }

    // Verify asymmetric ECDSA (secp256r1) signature from server
    private fun verifyAsymmetric(
        nonce: String,
        timestamp: Long,
        userId: String?,
        propertyName: String?,
        scope: String?,
        signatureB64: String
    ): Boolean {
    val effectiveKey = publicKeyBase64?.takeIf { it.isNotBlank() } ?: PUBLIC_KEY_B64
    if (effectiveKey.isBlank()) return false
    
    return try {
            val message = buildString {
                append(nonce)
                append(':')
                append(timestamp)
                append(':')
                append(userId ?: "-")
                append(':')
                append(propertyName ?: "-")
                append(':')
                append(scope ?: "-")
            }
            val pubBytes = android.util.Base64.decode(effectiveKey, android.util.Base64.NO_WRAP)
            val sigBytes = android.util.Base64.decode(signatureB64, android.util.Base64.NO_WRAP)
            val kf = java.security.KeyFactory.getInstance("EC")
            val pubSpec = java.security.spec.X509EncodedKeySpec(pubBytes)
            val pubKey = kf.generatePublic(pubSpec)
            val verifier = java.security.Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(pubKey)
            verifier.update(message.toByteArray(Charsets.UTF_8))
            verifier.verify(sigBytes)
        } catch (_: Exception) {
            false
        }
    }

    /** Prune nonce history if exceeding capacity */
    private fun pruneNonceHistoryIfNeeded(prefs: android.content.SharedPreferences) {
        val all = prefs.all
        if (all.size <= MAX_NONCE_HISTORY) return
        // Simple strategy: remove oldest 10% by timestamp
        val entries = all.filter { it.key.startsWith("nonce_") }
        if (entries.size <= MAX_NONCE_HISTORY) return
        val sorted = entries.mapNotNull { (k, v) ->
            if (v is Long) k to v else null
        }.sortedBy { it.second }
        val toRemove = sorted.take((sorted.size * 0.1).toInt().coerceAtLeast(1))
        val editor = prefs.edit()
        toRemove.forEach { editor.remove(it.first) }
        editor.apply()
        // Recompute MAC after pruning
        updateNonceStoreMac(prefs)
    }

    private data class Risk(val highRisk: Boolean)

    private fun assessRisk(context: Context): Risk {
        testHighRiskOverride?.let { return Risk(it) }
        
        // Use the centralized RiskDetector from the library
        val highRisk = io.mohammedalaamorsi.trckq.risk.RiskDetector.isHighRisk(context)
        return Risk(highRisk)
    }

    // --- Nonce store integrity MAC helpers ---
    private fun computeNonceStoreMac(prefs: android.content.SharedPreferences): String {
        return try {
            val entries = prefs.all
                .filter { it.key.startsWith("nonce_") && it.key != NONCE_MAC_KEY }
                .mapNotNull { (k, v) -> if (v is Long) k to v else null }
                .sortedBy { it.first } // canonical order by key
            val canonical = buildString {
                for ((k, v) in entries) {
                    append(k)
                    append(':')
                    append(v)
                    append('|')
                }
            }
            val mac = javax.crypto.Mac.getInstance("HmacSHA256")
            val keySpec = javax.crypto.spec.SecretKeySpec(NONCE_INTEGRITY_SECRET.toByteArray(Charsets.UTF_8), "HmacSHA256")
            mac.init(keySpec)
            val h = mac.doFinal(canonical.toByteArray(Charsets.UTF_8))
            android.util.Base64.encodeToString(h, android.util.Base64.NO_WRAP)
        } catch (e: Exception) {
            // Fallback simple hash
            (prefs.all.size.toString() + NONCE_INTEGRITY_SECRET).hashCode().toString(16)
        }
    }

    private fun verifyNonceStoreMac(prefs: android.content.SharedPreferences): Boolean {
        val stored = prefs.getString(NONCE_MAC_KEY, null) ?: return true // first-time initialization
        val expected = computeNonceStoreMac(prefs)
        return constantTimeEquals(stored, expected)
    }

    private fun updateNonceStoreMac(prefs: android.content.SharedPreferences) {
        val newMac = computeNonceStoreMac(prefs)
        prefs.edit { putString(NONCE_MAC_KEY, newMac) }
    }

    /**
     * Helper to request an integrity token to be sent to the backend.
     * 
     * @param context App context
     * @param nonce Nonce to bind the token to (get this from backend first)
     * @param cloudProjectNumber Your Google Cloud Project Number
     */
    suspend fun getIntegrityToken(
        context: Context,
        nonce: String,
        cloudProjectNumber: Long
    ): String {
        return io.mohammedalaamorsi.trckq.integrity.PlayIntegrityManager.requestIntegrityToken(
            context,
            nonce,
            cloudProjectNumber
        )
    }
}

/**
 * Extension functions for WriteKey validation logging
 */
fun WriteKey.validateAndLog(context: Context): Boolean {
    return when (val result = WriteKeyValidator.validate(this, context)) {
        is WriteKeyValidator.ValidationResult.Valid -> {
            println("✅ WriteKey Valid: $nonce")
            true
        }
        is WriteKeyValidator.ValidationResult.InvalidFormat -> {
            println("🚨 Invalid Format: ${result.reason} nonce=$nonce")
            false
        }
        is WriteKeyValidator.ValidationResult.Expired -> {
            println("🕒 Key Expired after ${result.ageMillis}ms nonce=$nonce")
            false
        }
        is WriteKeyValidator.ValidationResult.Replay -> {
            println("🔁 Replay Detected nonce=${result.nonce}")
            false
        }
        is WriteKeyValidator.ValidationResult.SignatureMismatch -> {
            println("🔒 Signature Mismatch expected=${result.expected} actual=${result.actual}")
            false
        }
        is WriteKeyValidator.ValidationResult.ClockSkewExceeded -> {
            println("⏱️ Clock Skew Exceeded skew=${result.skewMillis}ms nonce=$nonce")
            false
        }
        is WriteKeyValidator.ValidationResult.AsymSignatureMismatch -> {
            println("🔐 Asymmetric Signature Failure reason=${result.reason} nonce=$nonce")
            false
        }
        is WriteKeyValidator.ValidationResult.NonceStoreTampered -> {
            println("🧪 Nonce Store Tampered - rejecting key nonce=$nonce")
            false
        }
    }
}

/**
 * Extension to get WriteKey age in seconds
 */
fun WriteKey.ageSeconds(): Long {
    return (System.currentTimeMillis() - timestamp) / 1000
}

/**
 * Extension to get remaining TTL in seconds
 */
fun WriteKey.remainingTtlSeconds(): Long {
    val elapsed = System.currentTimeMillis() - timestamp
    val remaining = ttlMillis - elapsed
    return maxOf(0, remaining / 1000)
}
