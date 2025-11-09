package io.mohammedalaamorsi.trckq

import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

class SecureVarDelegate<T>(
    initialValue: T,
    private val propertyName: String
) : ReadWriteProperty<Any?, T> {

    private var state: SealedState<T>
    // Secrets sourced from TrckqManager's SecretProvider (fallback to static placeholders if absent)
    private val macSecret: String by lazy {
        TrckqManager.secretProvider?.getMacSecret() ?: "delegate-mac-secret"
    }
    private val encBaseSecret: String by lazy {
        TrckqManager.secretProvider?.getEncSecret(propertyName) ?: "delegate-enc-secret"
    }
    // Per-instance random salt to strengthen key derivation & MAC domain separation even when propertyName repeats.
    // This is NOT secret – it prevents cross-instance sealed state replay when the same propertyName is used.
    private val instanceSalt: String = generateSalt()
    // Rate limiting config
    private val writeLimitPerMinute: Int = 10
    private val writeWindowMillis: Long = 60_000

    init {
        state = seal(initialValue)
    }

    // GET remains the same: it always checks for tampering.
    override fun getValue(thisRef: Any?, property: KProperty<*>): T {
        val currentState = state
        if (currentState is SealedState.Sealed) {
            if (isTampered(currentState)) {
                TrckqManager.trigger("tamper.get", propertyName)
                // Return the value from the last known good state, or the initial default.
                val initialState = seal(getDefaultValue())
                return reconstructValue(initialState)
            }
            return reconstructValue(currentState)
        }
        // Fallback, should not happen if initialized correctly
        val initialState = seal(getDefaultValue())
        return reconstructValue(initialState)
    }

    // SET is now intentionally crippled. Direct assignment is FORBIDDEN.
    override fun setValue(thisRef: Any?, property: KProperty<*>, value: T) {
        // Trigger an alarm! Direct assignment is not allowed.
        TrckqManager.trigger("tamper.set", "Illegal direct assignment to $propertyName")
        // The write is IGNORED.
    }

    // The NEW, authorized way to write a value.
    fun authorizedWrite(newValue: T, key: WriteKey) {
        // Stack trace verification: ensure call originates from allowed package
        val allowedPrefix = "io.mohammedalaamorsi.trckqapp"
        val stackOk = Throwable().stackTrace.any { it.className.startsWith(allowedPrefix) }
        if (!stackOk) {
            TrckqManager.trigger("tamper.origin", "Unauthorized call site for $propertyName")
            return
        }

        // Rate limiting per variable
        if (!allowWriteNow()) {
            TrckqManager.trigger("tamper.rate", "Write rate exceeded for $propertyName")
            return
        }

        // 1. Validate the key via optional external verifier first (server logic mirrored locally)
        val externalVerifier = TrckqManager.writeKeyVerifier
        if (externalVerifier != null) {
            if (!externalVerifier.verify(key)) {
                TrckqManager.trigger("tamper.write", "External verifier rejected key for $propertyName")
                return
            }
            // If an external verifier is present and succeeded, we trust it and skip internal validation
        } else {
            // 2. Internal basic validation (nonce, ttl, signature). This consumes the nonce on success.
            if (!key.isValid()) {
                TrckqManager.trigger("tamper.write", "Invalid write key for $propertyName")
                return
            }
        }

        // 3. If the key is valid, re-seal the variable with the new value.
        this.state = seal(newValue)
    }

    private fun allowWriteNow(): Boolean {
        val now = System.currentTimeMillis()
        val q = Companion.writeHistory.getOrPut(propertyName) { ArrayDeque() }
        while (q.isNotEmpty() && now - q.first() > writeWindowMillis) {
            q.removeFirst()
        }
        if (q.size >= writeLimitPerMinute) {
            return false
        }
        q.addLast(now)
        return true
    }

    // Helper to create a sealed state
    private fun seal(value: T): SealedState.Sealed<T> {
        // Serialize value to string for encryption
        val plain = value.toString()
        val (ivB64, cipherB64) = encrypt(plain)
        val (pA, pB) = obfuscateAndSplit(cipherB64)
        val checksum = createChecksum(pA, pB)
        val mac = createMac(ivB64, cipherB64)
        return SealedState.Sealed(partA = pA, partB = pB, checksum = checksum, mac = mac, ivBase64 = ivB64, encrypted = true)
    }
    
    // Helper to check if state is tampered
    private fun isTampered(state: SealedState.Sealed<T>): Boolean {
        val expectedChecksum = createChecksum(state.partA, state.partB)
        if (expectedChecksum != state.checksum) return true
        val cipherB64 = deNoise(state.partA.toString()) + deNoise(state.partB.toString())
        val expectedMac = createMac(state.ivBase64 ?: "", cipherB64)
        return expectedMac != state.mac
    }
    
    // Obfuscate and split the value into two parts
    @Suppress("UNCHECKED_CAST")
    private fun obfuscateAndSplit(value: String): Pair<Any, Any> {
        // Simple obfuscation: split string and add random noise
        val stringValue = value
        val midPoint = stringValue.length / 2
        val partA = stringValue.take(midPoint) + System.nanoTime().toString().takeLast(4)
        val partB = stringValue.substring(midPoint) + System.nanoTime().toString().takeLast(4)
        return Pair(partA, partB)
    }
    
    // Reassemble and deobfuscate the value
    @Suppress("UNCHECKED_CAST")
    private fun reconstructValue(st: SealedState.Sealed<T>): T {
        val cipherB64 = deNoise(st.partA.toString()) + deNoise(st.partB.toString())
        val plain = if (st.encrypted) {
            decrypt(st.ivBase64 ?: return getDefaultValue(), cipherB64)
        } else {
            cipherB64
        }
        return parseToType(plain)
    }

    private fun deNoise(s: String): String = if (s.length > 4) s.dropLast(4) else ""

    @Suppress("UNCHECKED_CAST")
    private fun parseToType(text: String): T {
        return when {
            text == "true" || text == "false" -> text.toBoolean() as T
            text.toIntOrNull() != null -> text.toInt() as T
            text.toLongOrNull() != null -> text.toLong() as T
            else -> text as T
        }
    }
    
    // Create a checksum for the parts
    private fun createChecksum(partA: Any, partB: Any): Int {
        return (partA.hashCode() * 31 + partB.hashCode())
    }

    // Cryptographic MAC over obfuscated parts and property name
    private fun createMac(ivBase64: String, cipherB64: String): String {
        return try {
            val message = buildString {
                // Domain separation: propertyName + instanceSalt binds MAC to this delegate instance uniquely.
                append(propertyName)
                append(':')
                append(instanceSalt)
                append(':')
                append(ivBase64)
                append(':')
                append(cipherB64)
            }
            val mac = javax.crypto.Mac.getInstance("HmacSHA256")
            val key = javax.crypto.spec.SecretKeySpec(macSecret.toByteArray(Charsets.UTF_8), "HmacSHA256")
            mac.init(key)
            val h = mac.doFinal(message.toByteArray(Charsets.UTF_8))
            android.util.Base64.encodeToString(h, android.util.Base64.NO_WRAP)
        } catch (e: Exception) {
            // Fallback
            (propertyName + instanceSalt + ivBase64 + cipherB64 + macSecret).hashCode().toString(16)
        }
    }

    // AES-GCM Encryption helpers
    private fun encrypt(plainText: String): Pair<String, String> {
        return try {
            val iv = ByteArray(12)
            java.security.SecureRandom().nextBytes(iv)
            val keyBytes = java.security.MessageDigest.getInstance("SHA-256")
                .digest((encBaseSecret + ":" + propertyName + ":" + instanceSalt).toByteArray(Charsets.UTF_8))
            val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            val key = javax.crypto.spec.SecretKeySpec(keyBytes, "AES")
            val spec = javax.crypto.spec.GCMParameterSpec(128, iv)
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key, spec)
            val cipherBytes = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
            val ivB64 = android.util.Base64.encodeToString(iv, android.util.Base64.NO_WRAP)
            val cB64 = android.util.Base64.encodeToString(cipherBytes, android.util.Base64.NO_WRAP)
            ivB64 to cB64
        } catch (e: Exception) {
            // Fallback to no encryption
            "" to plainText
        }
    }

    private fun decrypt(ivBase64: String, cipherBase64: String): String {
        return try {
            val iv = android.util.Base64.decode(ivBase64, android.util.Base64.NO_WRAP)
            val cipherBytes = android.util.Base64.decode(cipherBase64, android.util.Base64.NO_WRAP)
            val keyBytes = java.security.MessageDigest.getInstance("SHA-256")
                .digest((encBaseSecret + ":" + propertyName + ":" + instanceSalt).toByteArray(Charsets.UTF_8))
            val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            val key = javax.crypto.spec.SecretKeySpec(keyBytes, "AES")
            val spec = javax.crypto.spec.GCMParameterSpec(128, iv)
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key, spec)
            val plainBytes = cipher.doFinal(cipherBytes)
            String(plainBytes, Charsets.UTF_8)
        } catch (e: Exception) {
            ""
        }
    }

    private fun generateSalt(): String {
        return try {
            val b = ByteArray(16)
            java.security.SecureRandom().nextBytes(b)
            android.util.Base64.encodeToString(b, android.util.Base64.NO_WRAP)
        } catch (e: Exception) {
            // Very unlikely; fallback to timestamp-based pseudo-random
            (System.nanoTime().toString() + propertyName).hashCode().toString(16)
        }
    }
    
    // Get initial value based on type
    @Suppress("UNCHECKED_CAST")
    private fun getInitialValue(): T {
        return when (state) {
            is SealedState.Sealed<*> -> {
                val current = state as SealedState.Sealed<T>
                reconstructValue(current)
            }
        }
    }

    // Default value used when tamper detected and decryption fails
    @Suppress("UNCHECKED_CAST")
    private fun getDefaultValue(): T {
        // Provide safe defaults based on simple heuristics
        return try {
            when (val v = reconstructValue(state as SealedState.Sealed<T>)) {
                is Boolean -> false as T
                is Int -> 0 as T
                is Long -> 0L as T
                is String -> "" as T
                else -> v
            }
        } catch (e: Exception) {
            when (state) {
                is SealedState.Sealed<*> -> {
                    // Best-effort
                    "" as T
                }
            }
        }
    }
}

// Sealed state to represent the obfuscated value
sealed class SealedState<T> {
    data class Sealed<T>(
        val partA: Any,
        val partB: Any,
        val checksum: Int,
        val mac: String,
        val ivBase64: String?,
        val encrypted: Boolean
    ) : SealedState<T>()
}

private typealias TimestampQueue = ArrayDeque<Long>

private object Companion {
    // Track write timestamps per property to enforce rate limiting
    val writeHistory: MutableMap<String, TimestampQueue> = mutableMapOf()
}

/**
 * WriteKey - A cryptographic key for authorizing secure variable writes
 * 
 * Features:
 * - Nonce-based (one-time use)
 * - Time-limited (expires after TTL)
 * - Replay attack prevention
 * - Optional signature verification
 */
data class WriteKey(
    val nonce: String,
    val timestamp: Long = System.currentTimeMillis(),
    val signature: String? = null,
    val ttlMillis: Long = DEFAULT_TTL_MILLIS,
    // Expanded context binding fields:
    val userId: String? = null,
    val propertyName: String? = null,
    val scope: String? = null, // e.g., "premium_status", "profile_update"
    val asymSignature: String? = null // Optional asymmetric signature (server-side ECDSA/Ed25519)
) {
    companion object {
        // Default time-to-live: 5 minutes
        private const val DEFAULT_TTL_MILLIS = 5 * 60 * 1000L
        
        // Track used nonces to prevent replay attacks
        private val usedNonces = mutableSetOf<String>()
        
        // Maximum nonces to track (prevent memory leak)
        private const val MAX_NONCE_CACHE_SIZE = 1000
        
        /**
         * Clear expired nonces from the cache
         */
        fun cleanupExpiredNonces() {
            // In a production app, you'd track nonces with their timestamps
            // and remove only expired ones. For simplicity, we clear all
            // when cache is full.
            if (usedNonces.size >= MAX_NONCE_CACHE_SIZE) {
                usedNonces.clear()
            }
        }
        
        /**
         * Create a server-generated write key with signature
         * This would typically be done on the backend
         */
        fun generate(
            secretKey: String = "app-secret-key",
            ttlMillis: Long = DEFAULT_TTL_MILLIS,
            userId: String? = null,
            propertyName: String? = null,
            scope: String? = null
        ): WriteKey {
            val nonce = generateNonce()
            val timestamp = System.currentTimeMillis()
            val signature = generateSignature(
                nonce = nonce,
                timestamp = timestamp,
                secretKey = secretKey,
                userId = userId,
                propertyName = propertyName,
                scope = scope
            )
            return WriteKey(nonce, timestamp, signature, ttlMillis, userId, propertyName, scope)
        }
        
        private fun generateNonce(): String {
            // Generate a cryptographically secure nonce
            val random = java.security.SecureRandom()
            val bytes = ByteArray(16)
            random.nextBytes(bytes)
            return bytes.joinToString("") { "%02x".format(it) }
        }
        
            /**
             * Generate HMAC-SHA256 signature for production use
             * 
             * @param nonce The unique nonce identifier
             * @param timestamp The creation timestamp
             * @param secretKey The secret key for signing (should be stored securely)
             * @return Base64-encoded HMAC-SHA256 signature
             */
            private fun generateSignature(
                nonce: String,
                timestamp: Long,
                secretKey: String,
                userId: String? = null,
                propertyName: String? = null,
                scope: String? = null
            ): String {
                return try {
                    // Create expanded message: nonce:timestamp:userId:propertyName:scope
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
                
                    // Get HMAC-SHA256 instance
                    val mac = javax.crypto.Mac.getInstance("HmacSHA256")
                
                    // Initialize with secret key
                    val secretKeySpec = javax.crypto.spec.SecretKeySpec(
                        secretKey.toByteArray(Charsets.UTF_8),
                        "HmacSHA256"
                    )
                    mac.init(secretKeySpec)
                
                    // Compute HMAC
                    val hmacBytes = mac.doFinal(message.toByteArray(Charsets.UTF_8))
                
                    // Encode to Base64 for transmission
                    android.util.Base64.encodeToString(
                        hmacBytes,
                        android.util.Base64.NO_WRAP
                    )
                } catch (e: Exception) {
                    // Fallback to SHA-256 hash if HMAC fails
                    try {
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
                            append(':')
                            append(secretKey)
                        }
                        val digest = java.security.MessageDigest.getInstance("SHA-256")
                        val hashBytes = digest.digest(message.toByteArray(Charsets.UTF_8))
                        android.util.Base64.encodeToString(
                            hashBytes,
                            android.util.Base64.NO_WRAP
                        )
                    } catch (e2: Exception) {
                        // Last resort fallback
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
    }
    
    /**
     * Validates the write key
     * Returns true if the key is legitimate and can be used
     */
    fun isValid(secretKey: String = "app-secret-key"): Boolean {
        // 1. Check nonce is not empty
        if (nonce.isBlank()) {
            return false
        }
        
        // 2. Check if nonce has already been used (replay attack prevention)
        if (usedNonces.contains(nonce)) {
            return false
        }
        
        // 3. Check if key has expired
        val currentTime = System.currentTimeMillis()
        if (currentTime - timestamp > ttlMillis) {
            return false
        }
        
        // 4. Verify signature if present
        signature?.let { sig ->
            val expectedSignature = generateSignature(
                nonce = nonce,
                timestamp = timestamp,
                secretKey = secretKey,
                userId = userId,
                propertyName = propertyName,
                scope = scope
            )
            if (sig != expectedSignature) {
                return false
            }
        }
        
        // 5. Mark nonce as used
        usedNonces.add(nonce)
        cleanupExpiredNonces()
        
        return true
    }
    
    /**
     * Check if the key has expired without consuming it
     */
    fun isExpired(): Boolean {
        return System.currentTimeMillis() - timestamp > ttlMillis
    }
    
    /**
     * Check if the nonce has been used
     */
    fun isUsed(): Boolean {
        return usedNonces.contains(nonce)
    }
    
        /**
         * Generate HMAC-SHA256 signature (instance method for validation)
         * 
         * This method mirrors the companion object's generateSignature
         * to ensure consistent signature generation during validation
         */
        private fun generateSignature(
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
            
                // Get HMAC-SHA256 instance
                val mac = javax.crypto.Mac.getInstance("HmacSHA256")
            
                // Initialize with secret key
                val secretKeySpec = javax.crypto.spec.SecretKeySpec(
                    secretKey.toByteArray(Charsets.UTF_8),
                    "HmacSHA256"
                )
                mac.init(secretKeySpec)
            
                // Compute HMAC
                val hmacBytes = mac.doFinal(message.toByteArray(Charsets.UTF_8))
            
                // Encode to Base64
                android.util.Base64.encodeToString(
                    hmacBytes,
                    android.util.Base64.NO_WRAP
                )
            } catch (e: Exception) {
                // Fallback to SHA-256 hash
                try {
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
                        append(':')
                        append(secretKey)
                    }
                    val digest = java.security.MessageDigest.getInstance("SHA-256")
                    val hashBytes = digest.digest(message.toByteArray(Charsets.UTF_8))
                    android.util.Base64.encodeToString(
                        hashBytes,
                        android.util.Base64.NO_WRAP
                    )
                } catch (e2: Exception) {
                    // Last resort fallback
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
}
