package io.mohammedalaamorsi.trckqapp.domain.usecase

import io.mohammedalaamorsi.trckqapp.domain.manager.SessionManager

/**
 * Use case for refreshing user status
 * Ensures the app always has the latest user data from the server
 */
class RefreshUserStatusUseCase(private val sessionManager: SessionManager) {
    
    suspend operator fun invoke(): Result<Unit> {
        return sessionManager.refreshUserStatus()
    }
}
