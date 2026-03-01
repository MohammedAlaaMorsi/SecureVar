package io.mohammedalaamorsi.securevarapp.data.model

/**
 * Data model representing the user profile response from the API
 */
data class UserProfile(
    val userId: String,
    val username: String,
    val email: String,
    val isPremium: Boolean,
    val writeKey: String, // Nonce component
    val writeKeyTimestamp: Long, // Server-issued timestamp for key
    val writeKeySignature: String?, // Server-generated HMAC signature
    val writeKeyScope: String?, // Scope of authorization (e.g., "premium_status", "profile_update")
    val writeKeyAsymSignature: String? // Optional server-issued asymmetric signature (ECDSA)
)
