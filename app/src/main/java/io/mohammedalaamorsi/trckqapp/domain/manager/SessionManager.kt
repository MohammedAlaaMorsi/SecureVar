package io.mohammedalaamorsi.trckqapp.domain.manager

import io.mohammedalaamorsi.trckq.SecureVarDelegate
import io.mohammedalaamorsi.trckq.WriteKey
import io.mohammedalaamorsi.trckqapp.security.WriteKeyValidator
import android.content.Context
import io.mohammedalaamorsi.trckq.secureVar
import io.mohammedalaamorsi.trckqapp.data.repository.UserRepository
import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

/**
 * Session Manager using SecureVar to protect premium status
 * This demonstrates the secure variable pattern from the trckq library
 */
class SessionManager(private val userRepository: UserRepository, private val appContext: Context) {

    // 1. Declare the variable with secureVar delegate
    // Direct assignment `isPremiumUser = ...` will now fail and trigger an alert
    var isPremiumUser: Boolean by secureVar(initialValue = false, propertyName = "isPremiumUser")
        private set // The setter is private, reinforcing that direct assignment is illegal

    var username: String by secureVar(initialValue = "", propertyName = "username")
        private set
    
    var userId: String by secureVar(initialValue = "", propertyName = "userId")
        private set

    // Called after login to initialize user session
    suspend fun login(email: String, password: String): Result<Unit> {
        return try {
            // 2. Fetch the user profile from the server (SOURCE OF TRUTH)
            val apiResponse = userRepository.login(email, password)

            // 3. Use the authorized writer to update secure variables
            val writeKey = WriteKeyValidator.fromServerResponse(
                nonce = apiResponse.writeKey,
                timestamp = apiResponse.writeKeyTimestamp,
                signature = apiResponse.writeKeySignature,
                asymSignature = apiResponse.writeKeyAsymSignature,
                userId = apiResponse.userId,
                scope = apiResponse.writeKeyScope,
                propertyName = "login" // Scope-level binding for multiple properties
            )

            // Write with validated key - delegate will validate internally
            secureVar(::isPremiumUser).write(
                newValue = apiResponse.isPremium,
                key = writeKey
            )

            secureVar(::username).write(
                newValue = apiResponse.username,
                key = writeKey
            )

            secureVar(::userId).write(
                newValue = apiResponse.userId,
                key = writeKey
            )

            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    // Called after a successful subscription purchase
    suspend fun purchaseSubscription(): Result<Unit> {
        return try {
            if (userId.isEmpty()) {
                return Result.failure(IllegalStateException("User not logged in"))
            }

            // 2. Fetch the LATEST user profile from the server
            // The server's response is the SOURCE OF TRUTH
            val apiResponse = userRepository.purchaseSubscription(userId)

            // The API response includes the user's status AND a one-time key
            // apiResponse = { "isPremium": true, "writeKey": "server-generated-nonce-12345" }

            // 3. Use the authorized writer to update the secure variable
            val writeKey = WriteKeyValidator.fromServerResponse(
                nonce = apiResponse.writeKey,
                timestamp = apiResponse.writeKeyTimestamp,
                signature = apiResponse.writeKeySignature,
                asymSignature = apiResponse.writeKeyAsymSignature,
                userId = apiResponse.userId,
                scope = apiResponse.writeKeyScope,
                propertyName = "isPremiumUser" // Must match the actual property name
            )
            
            // Write with validated key - delegate will validate internally
            secureVar(::isPremiumUser).write(
                newValue = apiResponse.isPremium,
                key = writeKey // Use the key from the server
            )

            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    // Refresh user status (e.g., on app resume or periodic checks)
    suspend fun refreshUserStatus(): Result<Unit> {
        return try {
            // 2. Fetch the LATEST user profile from the server
            // The server's response is the SOURCE OF TRUTH
            val apiResponse = userRepository.fetchUserProfileWithWriteKey()

            // The API response now includes the user's status AND a one-time key
            // apiResponse = { "isPremium": true, "writeKey": "server-generated-nonce-12345" }

            // 3. Use the authorized writer to update the secure variable
            val writeKey = WriteKeyValidator.fromServerResponse(
                nonce = apiResponse.writeKey,
                timestamp = apiResponse.writeKeyTimestamp,
                signature = apiResponse.writeKeySignature,
                asymSignature = apiResponse.writeKeyAsymSignature,
                userId = apiResponse.userId,
                scope = apiResponse.writeKeyScope,
                propertyName = "refresh" // Scope-level binding for status refresh
            )
            
            // Write with validated key - delegate will validate internally
            secureVar(::isPremiumUser).write(
                newValue = apiResponse.isPremium,
                key = writeKey // Use the key from the server
            )

            secureVar(::username).write(
                newValue = apiResponse.username,
                key = writeKey
            )

            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    // Attempt to hack the premium status (this will fail and trigger an alert)
    fun attemptDirectWrite() {
        // This will trigger the tamper detection!
        // The setValue() in SecureVarDelegate will trigger an alarm
        try {
            // This line would fail to compile due to private setter,
            // but if someone uses reflection or bytecode manipulation:
            isPremiumUser = true // This would trigger: TrckqManager.trigger("tamper.set", ...)
        } catch (e: Exception) {
            // Handle the exception
        }
    }

    fun logout() {
        // On logout, we still need the server's permission to reset values
        // In a real app, you'd call an API endpoint to get a write key for logout
        // For now, we'll just leave the values as-is
        // The next login will overwrite them with proper authorization
    }
}

// Helper function to create secureVar delegates (this should match the library implementation)
private fun <T> secureVar(
    initialValue: T,
    propertyName: String
): ReadWriteProperty<Any?, T> {
    return SecureVarDelegate(initialValue, propertyName)
}
