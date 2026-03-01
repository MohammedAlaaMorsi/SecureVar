package io.mohammedalaamorsi.securevarapp.domain.usecase

import io.mohammedalaamorsi.securevarapp.domain.manager.SessionManager

/**
 * Use case for user login
 * Encapsulates the business logic for authentication
 */
class LoginUseCase(private val sessionManager: SessionManager) {
    
    suspend operator fun invoke(email: String, password: String): Result<Unit> {
        // Validate input
        if (email.isBlank() || password.isBlank()) {
            return Result.failure(IllegalArgumentException("Email and password cannot be empty"))
        }
        
        // Delegate to session manager
        return sessionManager.login(email, password)
    }
}
