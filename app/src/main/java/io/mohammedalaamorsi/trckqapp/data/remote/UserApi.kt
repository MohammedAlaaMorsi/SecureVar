package io.mohammedalaamorsi.trckqapp.data.remote

import io.mohammedalaamorsi.trckqapp.data.model.UserProfile
import kotlinx.coroutines.delay

/**
 * Simulated API interface for user operations
 * In a real app, this would be a Retrofit interface
 */
interface UserApi {
    suspend fun fetchUserProfile(): UserProfile
    suspend fun login(email: String, password: String): UserProfile
    suspend fun purchaseSubscription(userId: String): UserProfile
}

/**
 * Mock implementation of UserApi for demonstration
 */
class MockUserApi : UserApi {
    
    private var sessionCounter = 0
    // Track premium status in-memory (simulating server-side state)
    private var userPremiumStatus = false
    
    override suspend fun fetchUserProfile(): UserProfile {
        // Simulate network delay
        delay(1000)
        
        // Generate a unique write key for each request
        val scope = "profile_refresh"
        val propertyName = "refresh" // Scope-level binding for multiple properties
        val userId = "user-123"
        val nonce = io.mohammedalaamorsi.trckq.WriteKey.generate(
            secretKey = APP_SECRET,
            userId = userId,
            propertyName = propertyName,
            scope = scope
        ).nonce
        val timestamp = System.currentTimeMillis()
        val signature = computeHmacSignature(nonce, timestamp, userId, propertyName, scope)
        val asymSignature = signAsymmetric(nonce, timestamp, userId, propertyName, scope)
        
        return UserProfile(
            userId = userId,
            username = "John Doe",
            email = "john.doe@example.com",
            isPremium = userPremiumStatus, // Return actual premium state
            writeKey = nonce,
            writeKeyTimestamp = timestamp,
            writeKeySignature = signature,
            writeKeyScope = scope,
            writeKeyAsymSignature = asymSignature
        )
    }
    
    override suspend fun login(email: String, password: String): UserProfile {
        // Simulate network delay
        delay(1500)
        
        // Reset premium status on new login
        userPremiumStatus = false
        
        val scope = "session_init"
        val propertyName = "login" // Scope-level binding for login
        val userId = "user-123"
        val nonce = io.mohammedalaamorsi.trckq.WriteKey.generate(
            secretKey = APP_SECRET,
            userId = userId,
            propertyName = propertyName,
            scope = scope
        ).nonce
        val timestamp = System.currentTimeMillis()
        val signature = computeHmacSignature(nonce, timestamp, userId, propertyName, scope)
        val asymSignature = signAsymmetric(nonce, timestamp, userId, propertyName, scope)
        
        return UserProfile(
            userId = userId,
            username = "John Doe",
            email = email,
            isPremium = userPremiumStatus, // Return actual state
            writeKey = nonce,
            writeKeyTimestamp = timestamp,
            writeKeySignature = signature,
            writeKeyScope = scope,
            writeKeyAsymSignature = asymSignature
        )
    }
    
    override suspend fun purchaseSubscription(userId: String): UserProfile {
        // Simulate network delay
        delay(2000)
        
        // Update server-side premium status
        userPremiumStatus = true
        
        val scope = "premium_status"
        val propertyName = "isPremiumUser" // Must match the actual property being updated
        val nonce = io.mohammedalaamorsi.trckq.WriteKey.generate(
            secretKey = APP_SECRET,
            userId = userId,
            propertyName = propertyName,
            scope = scope
        ).nonce
        val timestamp = System.currentTimeMillis()
        val signature = computeHmacSignature(nonce, timestamp, userId, propertyName, scope)
        val asymSignature = signAsymmetric(nonce, timestamp, userId, propertyName, scope)
        
        return UserProfile(
            userId = userId,
            username = "John Doe",
            email = "john.doe@example.com",
            isPremium = userPremiumStatus, // Return updated state
            writeKey = nonce,
            writeKeyTimestamp = timestamp,
            writeKeySignature = signature,
            writeKeyScope = scope,
            writeKeyAsymSignature = asymSignature
        )
    }

    companion object {
        private const val APP_SECRET = "your-app-secret-key-from-backend"
        // Generate an ephemeral ECDSA keypair for mock server signing (in real server, key stored securely)
        private val keyPair: java.security.KeyPair by lazy {
            val kpg = java.security.KeyPairGenerator.getInstance("EC")
            kpg.initialize(256)
            kpg.generateKeyPair().also { kp ->
                // Configure validator with public key
                val pubB64 = android.util.Base64.encodeToString(kp.public.encoded, android.util.Base64.NO_WRAP)
                io.mohammedalaamorsi.trckqapp.security.WriteKeyValidator.configurePublicKey(pubB64)
            }
        }

        private fun computeHmacSignature(
            nonce: String,
            timestamp: Long,
            userId: String?,
            propertyName: String?,
            scope: String?
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
                val secretKeySpec = javax.crypto.spec.SecretKeySpec(APP_SECRET.toByteArray(Charsets.UTF_8), "HmacSHA256")
                mac.init(secretKeySpec)
                val hmacBytes = mac.doFinal(message.toByteArray(Charsets.UTF_8))
                android.util.Base64.encodeToString(hmacBytes, android.util.Base64.NO_WRAP)
            } catch (e: Exception) {
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
                    append(APP_SECRET)
                }.hashCode().toString(16)
            }
        }

        private fun signAsymmetric(
            nonce: String,
            timestamp: Long,
            userId: String?,
            propertyName: String?,
            scope: String?
        ): String? {
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
                val signer = java.security.Signature.getInstance("SHA256withECDSA")
                signer.initSign(keyPair.private)
                signer.update(message.toByteArray(Charsets.UTF_8))
                val sig = signer.sign()
                android.util.Base64.encodeToString(sig, android.util.Base64.NO_WRAP)
            } catch (e: Exception) {
                null
            }
        }
    }
}
