package io.mohammedalaamorsi.securevar.integrity

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Helper class to securely bundle Google Play Integrity tokens
 * with WriteKey requests. This ensures that the backend can cryptographically
 * verify the device's integrity (Root/Hook/Emulator status) before issuing
 * a new WriteKey.
 */
object WriteKeyIntegrityBundler {

    /**
     * Bundles an Integrity Token with standard WriteKey request metadata.
     * Use the return value as the payload for your POST request to the backend.
     * 
     * @param context Application context
     * @param requestNonce Server-provided CSRF nonce or unique request ID
     * @param cloudProjectNumber Your Google Cloud Project number
     * @param userId (Optional) The user ID requesting the key
     * @param propertyName The secure property being requested
     * @param scope The scope of the requested key
     * @return A map of the request payload, ready to be serialized to JSON.
     */
    suspend fun createSecureWriteKeyRequestPayload(
        context: Context,
        requestNonce: String,
        cloudProjectNumber: Long,
        userId: String?,
        propertyName: String,
        scope: String
    ): Map<String, Any> = withContext(Dispatchers.IO) {
        
        // Retrieve the Integrity Token
        val token = try {
            PlayIntegrityManager.requestIntegrityToken(
                context = context,
                nonce = requestNonce, // Bind the token tightly to this specific request
                cloudProjectNumber = cloudProjectNumber
            )
        } catch (e: Exception) {
            // Depending on strictness, we might throw or send a fallback.
            // For zero-trust, if token fetch fails, the backend should reject it anyway.
            null
        }

        // Construct the secure payload
        val payload = mutableMapOf<String, Any>(
            "nonce" to requestNonce,
            "propertyName" to propertyName,
            "scope" to scope
        )
        
        userId?.let { payload["userId"] = it }
        token?.let { payload["integrityToken"] = it }
        
        return@withContext payload
    }
}
