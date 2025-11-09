package io.mohammedalaamorsi.trckqapp.data.repository

import io.mohammedalaamorsi.trckqapp.data.model.UserProfile

/**
 * Repository interface for user operations
 * This is the contract that the domain layer depends on
 */
interface UserRepository {
    suspend fun fetchUserProfileWithWriteKey(): UserProfile
    suspend fun login(email: String, password: String): UserProfile
    suspend fun purchaseSubscription(userId: String): UserProfile
}
