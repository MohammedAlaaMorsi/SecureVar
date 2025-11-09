package io.mohammedalaamorsi.trckqapp.data.repository

import io.mohammedalaamorsi.trckqapp.data.model.UserProfile
import io.mohammedalaamorsi.trckqapp.data.remote.UserApi

/**
 * Implementation of UserRepository
 * This class is responsible for coordinating data from different sources (API, cache, etc.)
 */
class UserRepositoryImpl(
    private val userApi: UserApi
) : UserRepository {
    
    override suspend fun fetchUserProfileWithWriteKey(): UserProfile {
        // In a real app, you might check cache first, handle errors, etc.
        return userApi.fetchUserProfile()
    }
    
    override suspend fun login(email: String, password: String): UserProfile {
        return userApi.login(email, password)
    }
    
    override suspend fun purchaseSubscription(userId: String): UserProfile {
        return userApi.purchaseSubscription(userId)
    }
}
